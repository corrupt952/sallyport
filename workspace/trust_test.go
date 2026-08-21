package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func trustSetup(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {}}`)
	return ConfigPath(dir)
}

func storeDir(t *testing.T) string {
	t.Helper()
	dir, err := trustDir()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestTrustLifecycle(t *testing.T) {
	path := trustSetup(t)

	if IsTrusted(path) {
		t.Fatal("config trusted before any approval")
	}
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(path) {
		t.Fatal("config not trusted after Trust")
	}
	if err := Untrust(path); err != nil {
		t.Fatal(err)
	}
	if IsTrusted(path) {
		t.Fatal("config still trusted after Untrust")
	}
}

func TestTrustExpiresWhenContentChanges(t *testing.T) {
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}

	writeConfig(t, filepath.Dir(path), `{"env": {"ADDED": "later"}}`)
	if IsTrusted(path) {
		t.Fatal("trust survived a content change")
	}
}

func TestTrustRejectsBrokenConfig(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {"$(whoami)": "x"}}`)
	if err := Trust(ConfigPath(dir)); err == nil {
		t.Fatal("expected error when trusting an unparseable config")
	}
}

func TestUntrustWithoutGrant(t *testing.T) {
	path := trustSetup(t)
	// Nothing has been trusted yet, so the store does not even exist: a missing
	// store must read as "never trusted", not as a failure to look.
	err := Untrust(path)
	if err == nil {
		t.Fatal("expected error when untrusting an unapproved config")
	}
	if !strings.HasPrefix(err.Error(), "not trusted:") {
		t.Fatalf("missing store: got %v, want a not-trusted error", err)
	}
}

func TestUntrustWithStoreHoldingNoMatch(t *testing.T) {
	other := trustSetup(t)
	if err := Trust(other); err != nil {
		t.Fatal(err)
	}
	// A second workspace nobody approved: the store exists and lists fine, so
	// this is the no-match verdict rather than the missing store above.
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {}}`)

	err := Untrust(ConfigPath(dir))
	if err == nil {
		t.Fatal("expected error when no record matches the config")
	}
	if !strings.HasPrefix(err.Error(), "not trusted:") {
		t.Fatalf("no matching record: got %v, want a not-trusted error", err)
	}
	if !IsTrusted(other) {
		t.Error("untrusting an unapproved config revoked another config's grant")
	}
}

func TestUntrustReportsUnlistableStore(t *testing.T) {
	skipIfRoot(t)
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// A store the user cannot read still passes verifyTrustStore, so the failure
	// surfaces only at the listing, with the grant still on disk: answering "not
	// trusted" would deny a trust that exists.
	store := storeDir(t)
	if err := os.Chmod(store, 0o000); err != nil {
		t.Fatal(err)
	}
	// Restore before t.TempDir's cleanup, which cannot remove an unreadable dir.
	t.Cleanup(func() { _ = os.Chmod(store, 0o700) })

	err := Untrust(path)
	if err == nil {
		t.Fatal("expected error when the trust store cannot be listed")
	}
	if strings.HasPrefix(err.Error(), "not trusted:") {
		t.Fatalf("unreadable store reported as not trusted: %v", err)
	}
	// Naming the store is what tells the user which directory to chmod.
	if !strings.Contains(err.Error(), store) {
		t.Errorf("got %v, want the underlying failure naming %s", err, store)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("got %v, want the underlying permission error", err)
	}
}

// The apply path has the same distinction to make as Untrust above, and more
// riding on it: the hook runs on every prompt, so the wrong answer here is what
// the user reads all day. "Not trusted" sends them to `sallyport trust`, which
// cannot fix a directory they need to chmod.
func TestLoadTrustedConfigSeparatesUnreadableStoreFromNoGrant(t *testing.T) {
	skipIfRoot(t)
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	store := storeDir(t)
	if err := os.Chmod(store, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(store, 0o700) })

	_, _, err := LoadTrustedConfig(path)
	if err == nil {
		t.Fatal("expected an error when the grant cannot be read")
	}
	if errors.Is(err, ErrUntrusted) {
		t.Fatalf("unreadable store reported as not trusted: %v", err)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("got %v, want the underlying permission error", err)
	}
	if !strings.Contains(err.Error(), store) {
		t.Errorf("got %v, want the failure naming %s", err, store)
	}
}

func TestUntrustSurfacesNonPermissionListingFailure(t *testing.T) {
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// os.Stat needs no descriptor, so verifyTrustStore sails through an exhausted
	// descriptor table while the ReadDir right after it fails with EMFILE. None
	// of these failures can be arranged on demand, hence listTrustStore.
	failure := &fs.PathError{Op: "open", Path: storeDir(t), Err: syscall.EMFILE}
	listTrustStore = func(string) ([]os.DirEntry, error) { return nil, failure }
	t.Cleanup(func() { listTrustStore = os.ReadDir })

	err := Untrust(path)
	if err == nil {
		t.Fatal("expected error when the trust store listing fails")
	}
	if strings.HasPrefix(err.Error(), "not trusted:") {
		t.Fatalf("listing failure reported as not trusted: %v", err)
	}
	if !errors.Is(err, syscall.EMFILE) {
		t.Errorf("got %v, want the listing failure itself", err)
	}
}

func TestUntrustReportsUnreadableRecord(t *testing.T) {
	skipIfRoot(t)
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// The store lists fine and only the record cannot be read. Skipping it leaves
	// the grant in force while the loop reports "not trusted", which also makes
	// the config impossible to revoke.
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d records after Trust, want 1", len(entries))
	}
	record := filepath.Join(storeDir(t), entries[0].Name())
	if err := os.Chmod(record, 0o000); err != nil {
		t.Fatal(err)
	}

	err = Untrust(path)
	if err == nil {
		t.Fatal("expected error when a record cannot be read")
	}
	if strings.HasPrefix(err.Error(), "not trusted:") {
		t.Fatalf("unreadable record reported as not trusted: %v", err)
	}
	if !strings.Contains(err.Error(), record) {
		t.Errorf("got %v, want the underlying failure naming %s", err, record)
	}
	// Stat needs no read permission, so the grant is demonstrably still there.
	if !IsTrusted(path) {
		t.Error("grant vanished; the unreadable record no longer proves the point")
	}
}

func TestUntrustSkipsDirectoriesInStore(t *testing.T) {
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// Reading a directory fails with EISDIR, and the unreadable-record branch
	// refuses to ignore a failed read, so one stray directory would otherwise
	// make every untrust impossible.
	if err := os.Mkdir(filepath.Join(storeDir(t), "stray"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := Untrust(path); err != nil {
		t.Fatalf("untrust failed with a stray directory in the store: %v", err)
	}
	if IsTrusted(path) {
		t.Error("config still trusted after Untrust")
	}
}

func TestUntrustIgnoresTmpLeftovers(t *testing.T) {
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// A leftover from an interrupted Trust records the same identity but is not a
	// grant: honoring it would report a revocation that removed nothing real,
	// while lookups, which test for the record name, still say untrusted.
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d records after Trust, want 1", len(entries))
	}
	leftover := filepath.Join(storeDir(t), entries[0].Name()+".tmp")
	if err := os.Rename(filepath.Join(storeDir(t), entries[0].Name()), leftover); err != nil {
		t.Fatal(err)
	}

	err = Untrust(path)
	if err == nil {
		t.Fatal("expected error when only a .tmp leftover names the config")
	}
	if !strings.HasPrefix(err.Error(), "not trusted:") {
		t.Fatalf("got %v, want a not-trusted error", err)
	}
	if _, err := os.Stat(leftover); err != nil {
		t.Errorf("leftover was consumed as a grant: %v", err)
	}
}

func TestUntrustRefusesInsecureStore(t *testing.T) {
	skipIfRoot(t)
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	store := storeDir(t)
	if err := os.Chmod(store, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(store, 0o700) })

	err := Untrust(path)
	if err == nil {
		t.Fatal("Untrust revoked from a group-writable store")
	}
	if strings.HasPrefix(err.Error(), "not trusted:") {
		t.Fatalf("insecure store reported as not trusted: %v", err)
	}
	// The grant stays put: the user must fix the store and untrust again, rather
	// than believe a revocation that ran against records anyone could forge.
	entries, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d records after the refused untrust, want 1", len(entries))
	}
}

func TestLoadTrustedConfig(t *testing.T) {
	path := trustSetup(t)

	if _, _, err := LoadTrustedConfig(path); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("unapproved config: got %v, want ErrUntrusted", err)
	}
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	if _, fp, err := LoadTrustedConfig(path); err != nil {
		t.Fatalf("approved config rejected: %v", err)
	} else if fp == "" {
		t.Fatal("approved config returned no fingerprint")
	}

	writeConfig(t, filepath.Dir(path), `{"env": {"ADDED": "later"}}`)
	if _, _, err := LoadTrustedConfig(path); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("edited config: got %v, want ErrUntrusted", err)
	}
}

// A grant is a file named after the fingerprint, and its existence is the whole
// approval, so the name has to be as hard to arrive at by accident as the
// digest that produces it. Shortening it invites a collision that authorizes a
// config nobody approved; changing the digest invalidates every grant on disk
// at once, silently, on upgrade. Both are one-token edits.
func TestFingerprintIsAFullSHA256(t *testing.T) {
	const path = "/ws/.sallyport.jsonc"
	const content = `{"env": {}}`
	got := fingerprintBytes(path, []byte(content))

	if len(got) != sha256.Size*2 {
		t.Errorf("fingerprint is %d hex chars, want %d: a shorter name collides sooner, and a different digest orphans every grant on disk", len(got), sha256.Size*2)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("fingerprint %q is not hex: %v", got, err)
	}
	want := sha256.Sum256([]byte(path + "\x00" + content))
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("fingerprint = %q, want %q: the digest is what every grant on disk is named by", got, hex.EncodeToString(want[:]))
	}

	// The separator is what keeps a path ending in one config's bytes from
	// hashing the same as a shorter path ending in another's.
	if a, b := fingerprintBytes("/a", []byte("b")), fingerprintBytes("/ab", nil); a == b {
		t.Error("path and content run together, so different pairs share a grant")
	}
}

func TestTrustViaAliasPath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	real := t.TempDir()
	writeConfig(t, real, `{"env": {}}`)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if err := Trust(ConfigPath(link)); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(ConfigPath(real)) {
		t.Error("grant via alias does not cover the canonical path")
	}
	if !IsTrusted(ConfigPath(link)) {
		t.Error("grant via alias does not cover the alias itself")
	}
}

func TestUntrustAfterEditRemovesStaleGrant(t *testing.T) {
	path := trustSetup(t)
	original := `{"env": {}}`

	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// Editing the config leaves the grant for the original bytes on disk while
	// changing the current fingerprint; Untrust must still find and remove it.
	writeConfig(t, filepath.Dir(path), `{"env": {"ADDED": "later"}}`)
	if err := Untrust(path); err != nil {
		t.Fatalf("untrust after edit failed: %v", err)
	}

	writeConfig(t, filepath.Dir(path), original)
	if IsTrusted(path) {
		t.Fatal("trust revived after restoring content of an untrusted config")
	}
}

func TestPruneRemovesTmpAndEmptyRecords(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {}}`)
	if err := Trust(ConfigPath(dir)); err != nil {
		t.Fatal(err)
	}
	id, err := configIdentity(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	// The leftover names a config that still exists, so only the .tmp suffix can
	// account for its removal: a payload naming a missing config would be swept
	// by the stale-grant branch even if .tmp cleanup were gone.
	if err := os.WriteFile(filepath.Join(storeDir(t), "leftover.tmp"), []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeDir(t), "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Prune(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d records after prune, want 1", len(entries))
	}
	if !IsTrusted(ConfigPath(dir)) {
		t.Error("prune removed a grant whose config still exists")
	}
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("root bypasses ownership and permission checks")
	}
}

func TestInsecureStoreInvalidatesGrants(t *testing.T) {
	skipIfRoot(t)
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(path) {
		t.Fatal("config not trusted after Trust")
	}
	// A group-writable store lets another user forge grants.
	if err := os.Chmod(storeDir(t), 0o770); err != nil {
		t.Fatal(err)
	}
	if IsTrusted(path) {
		t.Error("grant still honored from a group-writable store")
	}
	if _, _, err := LoadTrustedConfig(path); !errors.Is(err, ErrUnsafeTrustStore) {
		t.Errorf("LoadTrustedConfig: got %v, want ErrUnsafeTrustStore", err)
	}
}

func TestTrustRefusesInsecureStore(t *testing.T) {
	skipIfRoot(t)
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(storeDir(t), 0o707); err != nil {
		t.Fatal(err)
	}
	if err := Trust(path); err == nil {
		t.Error("Trust accepted a world-writable store")
	}
}

// unlocatableStoreCases are the environments in which trustDir has no absolute
// base to anchor the store on. rel is where the store would land relative to the
// working directory if the base were used anyway, which is where the tests below
// plant a grant.
var unlocatableStoreCases = []struct {
	name string
	// home and xdg are the values of HOME and XDG_DATA_HOME; empty means the
	// variable is absent rather than empty, which is what os.UserHomeDir reacts to.
	home string
	xdg  string
	rel  string
}{
	{name: "no home, no xdg", rel: filepath.Join(".local", "share")},
	{name: "relative home", home: "relhome", rel: filepath.Join("relhome", ".local", "share")},
	{name: "relative xdg", xdg: "reldata", rel: "reldata"},
}

// unlocatableStore applies one of those environments and moves the test into an
// empty working directory, where a store built from a relative base lands.
func unlocatableStore(t *testing.T, home, xdg string) string {
	t.Helper()
	// See withUnusableHome: with no home there is no boundary, and the walk to
	// the filesystem root would answer before the store lookup these cases are
	// about.
	t.Setenv(pathCheckOptOut, "1")
	// t.Setenv restores the previous value at cleanup even when the variable is
	// unset right after, which is how this package arranges for absence.
	t.Setenv("HOME", home)
	if home == "" {
		_ = os.Unsetenv("HOME")
	}
	t.Setenv("XDG_DATA_HOME", xdg)
	if xdg == "" {
		_ = os.Unsetenv("XDG_DATA_HOME")
	}
	cwd := t.TempDir()
	t.Chdir(cwd)
	return cwd
}

// assertNothingWritten reports any entry created under dir. It deliberately does
// not look for the store's own path segments: a fallback that was merely renamed
// or moved one directory up is still anchored wherever the user happens to
// stand, so the property is that nothing is written at all.
func assertNothingWritten(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("%s appeared in the working directory %s; the trust store must never be anchored there", e.Name(), dir)
	}
}

// A store whose location cannot be determined is not an empty store: answering
// as if it were let `trust` write a grant into the working directory, where
// `untrust` run one directory over reported "not trusted" while the grant was
// still on disk.
func TestTrustEntryPointsRefuseAnUnlocatableStore(t *testing.T) {
	for _, tc := range unlocatableStoreCases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := unlocatableStore(t, tc.home, tc.xdg)
			dir := t.TempDir()
			writeConfig(t, dir, `{"env": {}}`)
			path := ConfigPath(dir)

			err := Trust(path)
			if err == nil {
				t.Error("Trust recorded a grant with nowhere to record it")
			} else if !strings.Contains(err.Error(), "trust store") {
				// The user can only fix this by setting HOME or XDG_DATA_HOME.
				t.Errorf("Trust: got %v, want an error naming the trust store", err)
			}
			if IsTrusted(path) {
				t.Error("IsTrusted answered yes without a store to answer from")
			}
			if _, _, err := LoadTrustedConfig(path); !errors.Is(err, ErrUnsafeTrustStore) {
				t.Errorf("LoadTrustedConfig: got %v, want ErrUnsafeTrustStore", err)
			}
			err = Untrust(path)
			if err == nil {
				t.Error("Untrust reported success without a store to revoke from")
			} else if strings.HasPrefix(err.Error(), "not trusted:") {
				t.Errorf("unlocatable store reported as not trusted: %v", err)
			}
			if err := Prune(); err == nil {
				t.Error("Prune walked a store it could not locate")
			}
			assertNothingWritten(t, cwd)
		})
	}
}

// The dangerous half of the bug is not where `trust` writes but where the apply
// path reads: with the store anchored at the working directory, a cloned
// repository could ship .local/share/sallyport/trust/<fingerprint> next to its
// config and have its env applied on the first cd.
func TestUnlocatableStoreIgnoresGrantsPlantedInTheWorkingDirectory(t *testing.T) {
	for _, tc := range unlocatableStoreCases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := unlocatableStore(t, tc.home, tc.xdg)
			writeConfig(t, cwd, `{"env": {"PLANTED": "yes"}}`)
			path := ConfigPath(cwd)
			id, err := configIdentity(path)
			if err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(id)
			if err != nil {
				t.Fatal(err)
			}
			store := filepath.Join(cwd, tc.rel, "sallyport", "trust")
			if err := os.MkdirAll(store, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(store, fingerprintBytes(id, content)), []byte(id+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			cfg, _, err := LoadTrustedConfig(path)
			if !errors.Is(err, ErrUnsafeTrustStore) {
				t.Errorf("LoadTrustedConfig: got %v, want ErrUnsafeTrustStore", err)
			}
			if len(cfg.Env) != 0 {
				t.Errorf("planted grant applied %v", cfg.Env)
			}
			if IsTrusted(path) {
				t.Error("a grant planted in the working directory was honored")
			}
		})
	}
}

// The relative XDG_DATA_HOME is dropped, not fatal: HOME is still a good base
// and the spec says to fall back to it. Refusing every invocation that has one
// set would break users whose shell exports one.
func TestRelativeXDGDataHomeFallsBackToHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "reldata")
	cwd := t.TempDir()
	t.Chdir(cwd)
	// Inside the home, so the walk that checks the path stops there. A sibling
	// of the home is not below it, and the walk would carry on to the
	// filesystem root.
	dir := filepath.Join(home, "ws")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, dir, `{"env": {}}`)
	path := ConfigPath(dir)

	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(path) {
		t.Error("config not trusted after Trust")
	}
	entries, err := os.ReadDir(filepath.Join(home, ".local", "share", "sallyport", "trust"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d records in the home store, want 1", len(entries))
	}
	assertNothingWritten(t, cwd)
}

func TestTrustRefusesWritableConfigFile(t *testing.T) {
	skipIfRoot(t)
	path := trustSetup(t)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := Trust(path); err == nil {
		t.Error("Trust accepted a world-writable config file")
	}
}

func TestTrustRefusesWritableParentDir(t *testing.T) {
	skipIfRoot(t)
	path := trustSetup(t)
	// A world-writable parent allows a rename swap even if the file is read-only.
	if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := Trust(path); err == nil {
		t.Error("Trust accepted a config in a world-writable directory")
	}
}

func TestPruneRemovesStaleRecords(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	kept := t.TempDir()
	writeConfig(t, kept, `{"env": {}}`)
	gone := t.TempDir()
	writeConfig(t, gone, `{"env": {}}`)
	for _, p := range []string{ConfigPath(kept), ConfigPath(gone)} {
		if err := Trust(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(ConfigPath(gone)); err != nil {
		t.Fatal(err)
	}

	if err := Prune(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d records after prune, want 1", len(entries))
	}
	if !IsTrusted(ConfigPath(kept)) {
		t.Error("prune removed a grant whose config still exists")
	}
}

func TestPruneRefusesInsecureStore(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	kept := t.TempDir()
	writeConfig(t, kept, `{"env": {}}`)
	gone := t.TempDir()
	writeConfig(t, gone, `{"env": {}}`)
	for _, p := range []string{ConfigPath(kept), ConfigPath(gone)} {
		if err := Trust(p); err != nil {
			t.Fatal(err)
		}
	}
	// A record a walk would delete, so the refusal is observable in the store and
	// not only in the return value.
	if err := os.Remove(ConfigPath(gone)); err != nil {
		t.Fatal(err)
	}
	// Prune deletes records; in a store others can write to, what it reads as a
	// record's config path is their choice, so the walk acts on their input.
	store := storeDir(t)
	if err := os.Chmod(store, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(store, 0o700) })

	err := Prune()
	if err == nil {
		t.Fatal("Prune walked a group-writable store")
	}
	if !strings.Contains(err.Error(), store) {
		t.Errorf("got %v, want an error naming %s", err, store)
	}
	// The refusal has to come before the walk: reporting one after the records
	// are already gone is the same deletion with an error message attached.
	entries, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d records after the refused prune, want 2", len(entries))
	}
}

func TestPruneSurfacesNonPermissionListingFailure(t *testing.T) {
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// A store that cannot be listed is not an empty store: reporting "nothing to
	// prune" would turn every listing failure into a silent no-op.
	failure := &fs.PathError{Op: "open", Path: storeDir(t), Err: syscall.EMFILE}
	listTrustStore = func(string) ([]os.DirEntry, error) { return nil, failure }
	t.Cleanup(func() { listTrustStore = os.ReadDir })

	err := Prune()
	if err == nil {
		t.Fatal("expected error when the trust store listing fails")
	}
	if !errors.Is(err, syscall.EMFILE) {
		t.Errorf("got %v, want the listing failure itself", err)
	}
}

func TestPruneKeepsGrantWhenConfigCannotBeStatted(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {}}`)
	path := ConfigPath(dir)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// An unsearchable parent makes the stat fail with EACCES, which is not proof
	// the config is gone: pruning on that guess revokes a live approval, and the
	// user learns of it only the next time the workspace refuses to apply.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := Prune(); err != nil {
		t.Fatal(err)
	}
	// IsTrusted has to read the config, so the grant can only be checked once the
	// directory is searchable again.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(path) {
		t.Error("prune revoked a grant whose config it could not stat")
	}
}

// pruneOverDanglingSymlink trusts a config deployed as a symlink, removes its
// target the way a rebuild does mid-swap, and prunes. It returns the config
// path and the store's remaining entries.
func pruneOverDanglingSymlink(t *testing.T, base string) (string, []os.DirEntry) {
	t.Helper()
	target := filepath.Join(base, "store-1", "config")
	cfg := symlinkConfig(t, filepath.Join(base, "ws"), target, `{"env": {"A": "1"}}`)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := Prune(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, entries
}

func TestPruneKeepsGrantForDanglingConfigSymlink(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	// Mid-rebuild, a Nix-deployed config is a symlink whose target is briefly
	// gone. The config file itself is still there, so a prune run in that window
	// has no evidence the config was removed and must keep the record.
	_, entries := pruneOverDanglingSymlink(t, t.TempDir())

	if len(entries) != 1 {
		t.Errorf("got %d records after pruning over a dangling config symlink, want 1", len(entries))
	}
}

func TestPruneKeptGrantRevivesWhenSymlinkTargetIsReplaced(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	// The point of keeping the record: the rebuild finishes, identical content
	// lands at a new store path, and the approval the user already gave applies
	// again. This is what the prune in the middle must not have cost them.
	base := t.TempDir()
	cfg, _ := pruneOverDanglingSymlink(t, base)

	newTarget := filepath.Join(base, "store-2", "config")
	if err := os.MkdirAll(filepath.Dir(newTarget), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newTarget, []byte(`{"env": {"A": "1"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(newTarget, cfg); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(cfg) {
		t.Error("the record prune kept does not apply to the repointed symlink")
	}
}

func TestPruneSkipsUnreadableRecords(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	kept := t.TempDir()
	writeConfig(t, kept, `{"env": {}}`)
	gone := t.TempDir()
	writeConfig(t, gone, `{"env": {}}`)
	for _, p := range []string{ConfigPath(kept), ConfigPath(gone)} {
		if err := Trust(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(ConfigPath(gone)); err != nil {
		t.Fatal(err)
	}
	// One entry that cannot be read says nothing about the other records, so
	// prune has to walk past it: aborting would leave the store un-prunable
	// until the stray entry is cleaned up by hand.
	if err := os.WriteFile(filepath.Join(storeDir(t), "opaque"), []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(storeDir(t), "stray"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := Prune(); err != nil {
		t.Fatalf("prune failed on an unreadable entry: %v", err)
	}
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	// The kept grant, the unreadable file and the directory: only the stale grant
	// is gone, which proves the walk continued past the entry it could not read.
	if len(entries) != 3 {
		t.Errorf("got %d entries after prune, want 3", len(entries))
	}
	if !IsTrusted(ConfigPath(kept)) {
		t.Error("prune removed a grant whose config still exists")
	}
}

// trustZeroUmask clears the process umask for one test: the default 022 masks
// the very group and other bits these permissions are asserted to be free of.
// The umask is process-wide, so no test in this package may call t.Parallel.
// Call it after every t.TempDir the test needs: t.TempDir creates its numbered
// directories 0777 and leaves the narrowing to the umask, so one made without it
// is world-writable and refused by the config path checks.
func trustZeroUmask(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
}

func TestTrustWritesPrivateStoreAndRecords(t *testing.T) {
	path := trustSetup(t)
	trustZeroUmask(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}

	// A store others can write to lets them forge grants, which verifyTrustStore
	// then rejects, disabling every grant the user has.
	fi, err := os.Stat(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("trust store created with mode %04o, want no group or other bits", perm)
	}
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d records after Trust, want 1", len(entries))
	}
	// Nothing else checks a record's own mode, so a group-writable one would let
	// another user repoint an existing grant at a config of their choosing.
	ri, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if perm := ri.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("grant record created with mode %04o, want no group or other bits", perm)
	}
}

func TestCreateAutoTrusts(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	if err := Create(dir); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(ConfigPath(dir)) {
		t.Fatal("freshly created template is not trusted")
	}
}

// symlinkConfig makes dir a workspace whose .sallyport.jsonc is a symlink to
// target (written with content), the way Nix and home-manager deploy configs.
func symlinkConfig(t *testing.T, dir, target, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := ConfigPath(dir)
	if err := os.Symlink(target, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestTrustSymlinkedConfig(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := t.TempDir()
	cfg := symlinkConfig(t, filepath.Join(base, "ws"), filepath.Join(base, "store", "config"), `{"env": {}}`)

	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(cfg) {
		t.Fatal("symlinked config not trusted after Trust")
	}
}

func TestTrustSymlinkExpiresOnTargetEdit(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := t.TempDir()
	target := filepath.Join(base, "store", "config")
	cfg := symlinkConfig(t, filepath.Join(base, "ws"), target, `{"env": {}}`)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"env": {"ADDED": "x"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if IsTrusted(cfg) {
		t.Error("trust survived a target content change")
	}
}

func TestTrustSymlinkSurvivesTargetRepointSameContent(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := t.TempDir()
	cfg := symlinkConfig(t, filepath.Join(base, "ws"), filepath.Join(base, "store-1", "config"), `{"env": {"A": "1"}}`)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	// A Nix rebuild lands identical content at a new store path and repoints the
	// symlink. The identity is the logical location, not the target path.
	newTarget := filepath.Join(base, "store-2", "config")
	if err := os.MkdirAll(filepath.Dir(newTarget), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newTarget, []byte(`{"env": {"A": "1"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(newTarget, cfg); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(cfg) {
		t.Error("trust lost across a store-path change with identical content")
	}
}

func TestTrustSymlinkIdentityIsPerLocation(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := t.TempDir()
	target := filepath.Join(base, "store", "config")
	cfgA := symlinkConfig(t, filepath.Join(base, "a"), target, `{"env": {}}`)
	// Workspace b links to the very same target file.
	dirB := filepath.Join(base, "b")
	if err := os.MkdirAll(dirB, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgB := ConfigPath(dirB)
	if err := os.Symlink(target, cfgB); err != nil {
		t.Fatal(err)
	}

	if err := Trust(cfgA); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(cfgA) {
		t.Error("trusted workspace A reports untrusted")
	}
	if IsTrusted(cfgB) {
		t.Error("trusting A also trusted B despite a different logical location")
	}
}

func TestTrustDanglingSymlinkFails(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := t.TempDir()
	dir := filepath.Join(base, "ws")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := ConfigPath(dir)
	if err := os.Symlink(filepath.Join(base, "gone"), cfg); err != nil {
		t.Fatal(err)
	}
	err := Trust(cfg)
	if err == nil {
		t.Error("Trust accepted a dangling symlink config")
	} else if !strings.HasPrefix(err.Error(), "refusing to trust:") {
		// Only verifyConfigPath's refusal carries that prefix. Without it the
		// test passes on the read that fails afterwards, and would keep passing
		// with the path checks gone.
		t.Errorf("got %v, want the refusal from the path checks", err)
	}
	if IsTrusted(cfg) {
		t.Error("dangling symlink config reported trusted")
	}
}

func TestTrustRefusesSymlinkTargetWritable(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := t.TempDir()
	target := filepath.Join(base, "store", "config")
	cfg := symlinkConfig(t, filepath.Join(base, "ws"), target, `{"env": {}}`)
	// A writable target lets the reviewed bytes be rewritten after review.
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := Trust(cfg); err == nil {
		t.Error("Trust accepted a symlink to a world-writable target")
	}
}

func TestTrustRefusesSymlinkTargetParentWritable(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := t.TempDir()
	target := filepath.Join(base, "store", "config")
	cfg := symlinkConfig(t, filepath.Join(base, "ws"), target, `{"env": {}}`)
	// A writable target directory allows a rename swap of a read-only target.
	if err := os.Chmod(filepath.Dir(target), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := Trust(cfg); err == nil {
		t.Error("Trust accepted a symlink whose target directory is world-writable")
	}
}

func TestTrustAllowsStickyWritableTargetParent(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := t.TempDir()
	target := filepath.Join(base, "store", "config")
	cfg := symlinkConfig(t, filepath.Join(base, "ws"), target, `{"env": {}}`)
	// /nix/store is drwxrwxr-t: group-writable but sticky, which stops non-owners
	// from renaming entries, so the target cannot be swapped.
	if err := os.Chmod(filepath.Dir(target), 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := Trust(cfg); err != nil {
		t.Errorf("Trust rejected a config under a sticky writable directory: %v", err)
	}
	if !IsTrusted(cfg) {
		t.Error("config under a sticky writable directory not trusted")
	}
}

func TestTrustAllowsStickyWritableConfigParent(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, dir, `{"env": {}}`)
	// Same for a regular config directly inside a sticky world-writable directory.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := Trust(ConfigPath(dir)); err != nil {
		t.Errorf("Trust rejected a config in a sticky writable directory: %v", err)
	}
}
