package workspace

import (
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
	// Nothing has been trusted yet, so the store does not even exist. A missing
	// store holds no grants, which is the ordinary "never trusted" answer and
	// must read as such rather than as a failure to look.
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
	// A second workspace nobody approved. The store now exists and lists fine,
	// so this is the no-match verdict rather than the missing store above — the
	// ordinary way "not trusted" is reached, and the case the store-missing
	// branch defers to.
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
	// A store the user cannot read still passes verifyTrustStore: it is owned by
	// the user and writable by nobody else, which is all that check demands. The
	// failure therefore only surfaces when the records are listed, and the grant
	// is still on disk at that point, so answering "not trusted" would deny a
	// trust that exists and point the user at the wrong problem.
	store := trustDir()
	if err := os.Chmod(store, 0o000); err != nil {
		t.Fatal(err)
	}
	// Restore before t.TempDir's cleanup, which cannot remove an unreadable dir.
	t.Cleanup(func() { _ = os.Chmod(store, 0o700) })

	err := Untrust(path)
	if err == nil {
		t.Fatal("expected error when the trust store cannot be listed")
	}
	// The property is that no listing failure is answered with the verdict; an
	// assertion on the errno alone would still accept an implementation that
	// singles out EACCES and keeps lying about every other failure.
	if strings.HasPrefix(err.Error(), "not trusted:") {
		t.Fatalf("unreadable store reported as not trusted: %v", err)
	}
	// Naming the store is what tells the user which directory to chmod, so the
	// real failure has to come through rather than a stand-in built from scratch.
	if !strings.Contains(err.Error(), store) {
		t.Errorf("got %v, want the underlying failure naming %s", err, store)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("got %v, want the underlying permission error", err)
	}
}

func TestUntrustSurfacesNonPermissionListingFailure(t *testing.T) {
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// A permission denial is not the only way the listing fails, and the others
	// are not hypothetical: os.Stat needs no descriptor, so verifyTrustStore
	// sails through an exhausted descriptor table while the ReadDir right after
	// it fails with EMFILE. EIO and a stale NFS handle land the same way. None
	// of them can be arranged from a test on demand, hence listTrustStore.
	failure := &fs.PathError{Op: "open", Path: trustDir(), Err: syscall.EMFILE}
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
	// Here the store lists fine and only the record cannot be read. Skipping it
	// leaves the grant in force while the loop finds no match and reports "not
	// trusted": the same lie as an unlistable store, one level down, and this
	// one also makes the config impossible to revoke.
	entries, err := os.ReadDir(trustDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d records after Trust, want 1", len(entries))
	}
	record := filepath.Join(trustDir(), entries[0].Name())
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
	// Stat needs no read permission, so the grant is demonstrably still there:
	// this is exactly the trust that a "not trusted" answer would have denied.
	if !IsTrusted(path) {
		t.Error("grant vanished; the unreadable record no longer proves the point")
	}
}

func TestUntrustSkipsDirectoriesInStore(t *testing.T) {
	path := trustSetup(t)
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// Nothing sallyport writes puts a directory in the store, but reading one
	// fails with EISDIR, and the unreadable-record branch refuses to ignore a
	// failed read. Without the directory being stepped over, one stray directory
	// would make every untrust impossible.
	if err := os.Mkdir(filepath.Join(trustDir(), "stray"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := Untrust(path); err != nil {
		t.Fatalf("untrust failed with a stray directory in the store: %v", err)
	}
	if IsTrusted(path) {
		t.Error("config still trusted after Untrust")
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

	// Restoring the original content must not revive trust: the stale grant is
	// gone, so this is the regression that motivated matching records by path.
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
	// A crashed write of an older version can leave a .tmp leftover and an
	// empty record; both must be pruned while the real grant survives.
	if err := os.WriteFile(filepath.Join(trustDir(), "leftover.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustDir(), "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Prune(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(trustDir())
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
	// A group-writable store lets another user forge grants, so every grant it
	// holds must stop counting until the mode is fixed.
	if err := os.Chmod(trustDir(), 0o770); err != nil {
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
	// World-writable store: adding a grant to it would let anyone tamper with
	// the whole set.
	if err := os.Chmod(trustDir(), 0o707); err != nil {
		t.Fatal(err)
	}
	if err := Trust(path); err == nil {
		t.Error("Trust accepted a world-writable store")
	}
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
	// A world-writable parent lets an attacker replace the reviewed config by
	// rename even if the file itself is read-only.
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
	entries, err := os.ReadDir(trustDir())
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
// It returns the config path inside dir.
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
	// Rewriting the target's bytes changes the fingerprint, so the grant for the
	// original content no longer matches: an edit through the link revokes trust.
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
	// symlink. The identity is the logical location, not the target path, so the
	// fingerprint is unchanged and trust must survive.
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
	if err := Trust(cfg); err == nil {
		t.Error("Trust accepted a dangling symlink config")
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
	// A group/world-writable target lets an attacker rewrite the bytes the link
	// resolves to after the human reviewed them.
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
	// A writable target directory lets the target be swapped by rename even when
	// the target file itself is read-only.
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
	// /nix/store is drwxrwxr-t: group-writable but sticky. Sticky stops
	// non-owners from renaming entries, so a root-owned target cannot be
	// swapped, and the config must still be trustable.
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
	// A regular config directly inside a sticky, world-writable directory is
	// safe for the same reason: sticky blocks the rename-swap.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := Trust(ConfigPath(dir)); err != nil {
		t.Errorf("Trust rejected a config in a sticky writable directory: %v", err)
	}
}
