package workspace

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// grantFor is the record a grant for path's current bytes would take. Tests
// plant and inspect records through it rather than listing the store, so what
// is asserted is the exact name a lookup goes for.
func grantFor(t *testing.T, path string) string {
	t.Helper()
	id, err := configIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(id)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(storeDir(t), fingerprintBytes(id, content))
}

// onlyRecord returns the store's single entry, failing when there is not
// exactly one.
func onlyRecord(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d records, want 1", len(entries))
	}
	return filepath.Join(storeDir(t), entries[0].Name())
}

// capturedProgress collects what Info/Ok/Warn write while fn runs.
func capturedProgress(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	out = &buf
	t.Cleanup(func() { out = nil })
	fn()
	out = nil
	return buf.String()
}

// A-45: a store that does not exist yet holds no grants and is not a failure;
// the first Trust creates it. A verdict that changes across that boundary is
// how "it worked once and never again" starts.
func TestTrustCreatesAPrivateStoreOnFirstUse(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))

	if IsTrusted(cfg) {
		t.Fatal("config trusted before any approval")
	}
	if _, err := os.Stat(storeDir(t)); !os.IsNotExist(err) {
		t.Fatalf("store exists before the first Trust: %v", err)
	}
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("store created with mode %04o, want no group or other bits", perm)
	}
	if !IsTrusted(cfg) {
		t.Error("config not trusted after Trust")
	}
}

// A-46: a grant is a file whose mere existence authorizes applying a config, so
// anyone who can write into the store can forge one. Read access is not the
// same exposure and must not be refused along with it.
func TestStoreModesDecideWhetherGrantsCount(t *testing.T) {
	cases := []struct {
		mode   os.FileMode
		accept bool
	}{
		{mode: 0o700, accept: true},
		{mode: 0o750, accept: true},
		// Readable and searchable by others, writable by nobody but the owner:
		// forging a grant means creating a file, which read access does not allow.
		{mode: 0o705, accept: true},
		{mode: 0o770},
		{mode: 0o777},
		{mode: 0o707},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%04o", tc.mode), func(t *testing.T) {
			home := pathCheckHome(t)
			cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
			if err := Trust(cfg); err != nil {
				t.Fatal(err)
			}
			chmodMode(t, storeDir(t), tc.mode)

			if got := IsTrusted(cfg); got != tc.accept {
				t.Errorf("IsTrusted = %v with a %04o store, want %v", got, tc.mode, tc.accept)
			}
			_, _, err := LoadTrustedConfig(cfg)
			if tc.accept {
				if err != nil {
					t.Errorf("LoadTrustedConfig refused a %04o store: %v", tc.mode, err)
				}
				if err := Trust(cfg); err != nil {
					t.Errorf("Trust refused a %04o store: %v", tc.mode, err)
				}
				return
			}
			if !errors.Is(err, ErrUnsafeTrustStore) {
				t.Errorf("LoadTrustedConfig: got %v, want ErrUnsafeTrustStore", err)
			}
			if err := Trust(cfg); err == nil {
				t.Errorf("Trust accepted a %04o store", tc.mode)
			}
		})
	}
}

// A-47: every entry point has to reach the same verdict about the store. One
// that skips the check is a way back in for grants the others refuse.
func TestEveryEntryPointRefusesAForeignStore(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	store := storeDir(t)
	chownTo(t, store, foreignUID())

	if IsTrusted(cfg) {
		t.Error("IsTrusted honored a store owned by another user")
	}
	if err := Trust(cfg); err == nil {
		t.Error("Trust wrote into a store owned by another user")
	}
	if err := Untrust(cfg); err == nil || strings.HasPrefix(err.Error(), "not trusted:") {
		t.Errorf("Untrust: got %v, want a refusal naming the store", err)
	}
	if err := Prune(); err == nil {
		t.Error("Prune walked a store owned by another user")
	}
	res, err := BuildExportScript(ws, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Script, "FOO=") {
		t.Errorf("applied a config on a grant from a foreign store:\n%s", res.Script)
	}
	if !hasWarning(res.Warnings, store) {
		t.Errorf("got warnings %q, want one naming %s", res.Warnings, store)
	}
}

// A-48: a root-owned store is the shape /opt/sallyport takes, and refusing it
// while the config side accepts root-owned files is a rule the user cannot
// derive from either half.
func TestStoreOwnedByRootIsAccepted(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	store := storeDir(t)
	chownTo(t, onlyRecord(t), 0)
	chownTo(t, store, 0)

	if !IsTrusted(cfg) {
		t.Error("a grant in a root-owned store is ignored")
	}
	if _, _, err := LoadTrustedConfig(cfg); err != nil {
		t.Errorf("LoadTrustedConfig refused a root-owned store: %v", err)
	}
}

// A-49: a file where the store should be is a mistake the user can fix, but
// only if the error says which file and what to do with it.
func TestStorePathHoldingAFileIsReported(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	store := storeDir(t)
	mkdirMode(t, filepath.Dir(store), 0o700)
	if err := os.WriteFile(store, []byte("not a store"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Trust(cfg)
	assertRefusedNaming(t, err, store)
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("got %v, want an error saying it is not a directory", err)
	}
}

// A-50: a dangling symlink where the store should be reads as absent and then
// fails to be created. The raw EEXIST alone leaves nothing to act on.
func TestStorePathHoldingADanglingSymlinkIsReported(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	store := storeDir(t)
	mkdirMode(t, filepath.Dir(store), 0o700)
	if err := os.Symlink(filepath.Join(home, "gone"), store); err != nil {
		t.Fatal(err)
	}

	assertRefusedNaming(t, Trust(cfg), store)
	if IsTrusted(cfg) {
		t.Error("a config is trusted through a store that could not be created")
	}
}

// A-51: Stat follows the link, so the store's own node goes unexamined. Whoever
// can write the directory it sits in decides which store sallyport reads.
func TestStoreReachedThroughASymlinkInAWritableDirectory(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	real := filepath.Join(home, "real-store")
	mkdirMode(t, real, 0o700)
	xdg := filepath.Join(home, "xdg")
	mkdirMode(t, filepath.Join(xdg, "sallyport"), 0o777)
	t.Setenv("XDG_DATA_HOME", xdg)
	if err := os.Symlink(real, filepath.Join(xdg, "sallyport", "trust")); err != nil {
		t.Fatal(err)
	}

	assertRefusedNaming(t, Trust(cfg), filepath.Join(xdg, "sallyport"))
}

// A-52: a writable parent lets the store itself be renamed away, which puts a
// snapshot taken before a revocation back in force.
func TestStoreParentMustNotBeWritable(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(storeDir(t))
	chmodMode(t, parent, 0o777)

	assertRefusedNaming(t, Trust(cfg), parent)
	if IsTrusted(cfg) {
		t.Error("grants are honored from a store whose parent anyone can rename")
	}
	res, err := BuildExportScript(ws, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Script, "FOO=") {
		t.Errorf("applied a config on a grant from a movable store:\n%s", res.Script)
	}
}

// A-53: the store's ancestry needs the same walk the config's gets. Fixing one
// side and forgetting the other is the shape this has taken before.
func TestStoreAncestryIsWalkedToHome(t *testing.T) {
	levels := map[string]string{
		"share": filepath.Join(".local", "share"),
		"local": ".local",
		"home":  ".",
	}
	breakage := map[string]func(t *testing.T, dir string){
		"world-writable":  func(t *testing.T, dir string) { chmodMode(t, dir, 0o777) },
		"owned by others": func(t *testing.T, dir string) { chownTo(t, dir, foreignUID()) },
	}
	for levelName, rel := range levels {
		for breakName, arrange := range breakage {
			t.Run(levelName+"/"+breakName, func(t *testing.T) {
				home := pathCheckHome(t)
				ws := filepath.Join(home, "ws")
				cfg := newWorkspaceAt(t, ws)
				if err := Trust(cfg); err != nil {
					t.Fatal(err)
				}
				node := filepath.Clean(filepath.Join(home, rel))
				arrange(t, node)

				assertRefusedNaming(t, Trust(cfg), node)
				if IsTrusted(cfg) {
					t.Errorf("grants are honored with %s reachable by others", node)
				}
				res, err := BuildExportScript(ws, false)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(res.Script, "FOO=") {
					t.Errorf("applied a config from a store under %s:\n%s", node, res.Script)
				}
			})
		}
	}
}

// A-54: the sticky exemption has to hold on the store side too, or an
// XDG_DATA_HOME under /tmp stops working for reasons the mode bits do not
// explain.
func TestStoreUnderAStickyWritableDirectoryIsAccepted(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	tmp := filepath.Join(home, "tmp")
	mkdirMode(t, tmp, 0o777|os.ModeSticky)
	xdg := filepath.Join(tmp, fmt.Sprintf("xdg-%d", os.Getuid()))
	mkdirMode(t, xdg, 0o700)
	t.Setenv("XDG_DATA_HOME", xdg)

	if err := Trust(cfg); err != nil {
		t.Fatalf("refused a store under a sticky writable directory: %v", err)
	}
	if !IsTrusted(cfg) {
		t.Error("config not trusted after Trust")
	}
}

// withUnusableHome applies a HOME that cannot anchor a store, clears
// XDG_DATA_HOME, and moves the test into an empty working directory, which is
// where a store built from a relative base lands.
func withUnusableHome(t *testing.T, home string, unset bool) string {
	t.Helper()
	// Without a home there is no boundary, so the walk runs to the filesystem
	// root, and these cases are about where the store is looked for rather than
	// about the path above it. Leaving the walk on would report whoever owns the
	// root -- under a Nix builder the sandbox's root, owned by neither the build
	// user nor root -- in place of the answer under test.
	t.Setenv(pathCheckOptOut, "1")
	t.Setenv("HOME", home)
	if unset {
		_ = os.Unsetenv("HOME")
	}
	t.Setenv("XDG_DATA_HOME", "")
	_ = os.Unsetenv("XDG_DATA_HOME")
	cwd := t.TempDir()
	t.Chdir(cwd)
	return cwd
}

// A-55..A-57: without an absolute base there is no store, and answering as if
// there were an empty one anchors it at the working directory: a cloned
// repository could then carry its own grants and be applied on the first cd.
func TestUnusableHomeIsRefusedRatherThanAnchoredAtTheCwd(t *testing.T) {
	cases := []struct {
		id, name string
		home     string
		unset    bool
	}{
		{id: "A-55", name: "absent", unset: true},
		{id: "A-56", name: "empty"},
		{id: "A-57", name: "relative", home: filepath.Join("relative", "home")},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			cwd := withUnusableHome(t, tc.home, tc.unset)
			dir := filepath.Join(cwd, "ws")
			cfg := newWorkspaceAt(t, dir)

			err := Trust(cfg)
			if err == nil {
				t.Error("Trust recorded a grant with nowhere to record it")
			} else if !strings.Contains(err.Error(), "trust store") {
				t.Errorf("got %v, want an error naming the trust store", err)
			}
			if IsTrusted(cfg) {
				t.Error("IsTrusted answered yes without a store to answer from")
			}
			if _, _, err := LoadTrustedConfig(cfg); !errors.Is(err, ErrUnsafeTrustStore) {
				t.Errorf("LoadTrustedConfig: got %v, want ErrUnsafeTrustStore", err)
			}
			if err := Untrust(cfg); err == nil || strings.HasPrefix(err.Error(), "not trusted:") {
				t.Errorf("Untrust: got %v, want a refusal naming the store", err)
			}
			if err := Prune(); err == nil {
				t.Error("Prune walked a store it could not locate")
			}
		})
	}
}

// A-58: HOME naming a directory that is not there yet is not an attack, and the
// store created under it has to come out private all the same. This pins the
// current answer, which is to create the whole chain.
func TestHomeThatDoesNotExistYet(t *testing.T) {
	base := pathCheckBase(t)
	skipIfHostTreeIsUnsafe(t, base)
	home := filepath.Join(base, "not-yet")
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	cfg := newWorkspaceAt(t, filepath.Join(base, "ws"))

	if err := Trust(cfg); err != nil {
		t.Fatalf("Trust failed with a home that does not exist: %v", err)
	}
	fi, err := os.Stat(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("store created with mode %04o, want no group or other bits", perm)
	}
	if !IsTrusted(cfg) {
		t.Error("config not trusted after Trust")
	}
}

// A-59, A-110: a relative XDG_DATA_HOME is dropped in favour of HOME, and the
// quoted-tilde spelling shells produce by accident is just another relative
// value. What must never happen is a store, or a directory named "~", appearing
// beside whatever the user happens to be standing in.
func TestRelativeXDGDataHomeNeverAnchorsTheStoreAtTheCwd(t *testing.T) {
	for _, xdg := range []string{"reldata", "~/.local/share", "./data"} {
		t.Run(xdg, func(t *testing.T) {
			home := pathCheckHome(t)
			t.Setenv("XDG_DATA_HOME", xdg)
			cwd := t.TempDir()
			t.Chdir(cwd)
			cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))

			if err := Trust(cfg); err != nil {
				t.Fatalf("Trust failed with a relative XDG_DATA_HOME: %v", err)
			}
			if _, err := os.Stat(filepath.Join(home, ".local", "share", "sallyport", "trust")); err != nil {
				t.Errorf("the store did not fall back to HOME: %v", err)
			}
			assertNothingWritten(t, cwd)
		})
	}
}

// A-60: a store inside the workspace it approves is a store the workspace can
// ship. Cloning the repository would then apply its env without anyone
// approving anything.
func TestStoreInsideTheWorkspaceIsRefused(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	xdg := filepath.Join(ws, ".sallyport-data")
	mkdirMode(t, xdg, 0o700)
	t.Setenv("XDG_DATA_HOME", xdg)

	if err := Trust(cfg); err == nil {
		t.Error("Trust wrote a grant into the workspace it was approving")
	}
	if IsTrusted(cfg) {
		t.Error("a grant shipped inside the workspace was honored")
	}
}

// A-61: a store outside HOME is a legitimate setting, and the walk that gets
// skipped when the config's stops at HOME still has to happen for the store.
func TestStoreAboveHomeIsAcceptedButStillWalked(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		base := pathCheckBase(t)
		skipIfHostTreeIsUnsafe(t, base)
		home := filepath.Join(base, "home")
		mkdirMode(t, home, 0o755)
		t.Setenv("HOME", home)
		t.Setenv("XDG_DATA_HOME", base)
		cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))

		if err := Trust(cfg); err != nil {
			t.Fatalf("refused a store above HOME: %v", err)
		}
	})
	t.Run("still walked", func(t *testing.T) {
		base := pathCheckBase(t)
		skipIfHostTreeIsUnsafe(t, base)
		home := filepath.Join(base, "home")
		mkdirMode(t, home, 0o755)
		data := filepath.Join(base, "data")
		mkdirMode(t, data, 0o700)
		t.Setenv("HOME", home)
		t.Setenv("XDG_DATA_HOME", data)
		cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
		if err := Trust(cfg); err != nil {
			t.Fatal(err)
		}
		chmodMode(t, base, 0o777)

		assertRefusedNaming(t, Trust(cfg), base)
		if IsTrusted(cfg) {
			t.Error("grants are honored from a store under a world-writable directory")
		}
	})
}

// A-62..A-64: the store's location must not depend on how XDG_DATA_HOME is
// spelled, or the same shell config applied twice lands in two places.
func TestStoreLocationIgnoresXDGSpelling(t *testing.T) {
	cases := []struct {
		id, name string
		// xdg builds the value from home; an empty result means the variable is
		// set to the empty string.
		xdg func(home string) string
	}{
		{id: "A-62", name: "trailing slash", xdg: func(home string) string {
			return filepath.Join(home, "data") + "/"
		}},
		{id: "A-62", name: "doubled separator", xdg: func(home string) string {
			return filepath.Join(home, "data") + "//"
		}},
		{id: "A-63", name: "empty", xdg: func(home string) string { return "" }},
		{id: "A-64", name: "home itself", xdg: func(home string) string { return home }},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			home := pathCheckHome(t)
			mkdirMode(t, filepath.Join(home, "data"), 0o700)
			cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
			t.Setenv("XDG_DATA_HOME", tc.xdg(home))

			if err := Trust(cfg); err != nil {
				t.Fatalf("Trust failed: %v", err)
			}
			if !IsTrusted(cfg) {
				t.Error("the grant just written is not found again")
			}
			// The same store under the plain spelling holds the record, so the
			// value was normalized rather than turned into a second store.
			t.Setenv("XDG_DATA_HOME", strings.TrimRight(tc.xdg(home), "/"))
			if !IsTrusted(cfg) {
				t.Error("the grant is invisible under the normalized spelling")
			}
		})
	}
}

// A-65: /home is a symlink to somewhere else often enough. One approval has to
// cover both spellings of the same home.
func TestHomeReachedThroughASymlink(t *testing.T) {
	base := pathCheckBase(t)
	skipIfHostTreeIsUnsafe(t, base)
	real := filepath.Join(base, "real-home")
	mkdirMode(t, real, 0o755)
	link := filepath.Join(base, "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", link)
	t.Setenv("XDG_DATA_HOME", "")
	cfg := newWorkspaceAt(t, filepath.Join(real, "ws"))

	if err := Trust(cfg); err != nil {
		t.Fatalf("refused a home reached through a symlink: %v", err)
	}
	t.Setenv("HOME", real)
	if !IsTrusted(cfg) {
		t.Error("the grant is invisible once HOME is spelled without the symlink")
	}
}

// A-66: a HOME pointing into someone else's home is a misconfiguration that
// would otherwise have sallyport writing grants there.
func TestHomeOwnedByAnotherUserIsRefused(t *testing.T) {
	base := pathCheckBase(t)
	skipIfHostTreeIsUnsafe(t, base)
	home := filepath.Join(base, "theirs")
	mkdirMode(t, home, 0o755)
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	cfg := newWorkspaceAt(t, filepath.Join(base, "ws"))
	chownTo(t, home, foreignUID())

	assertRefusedNaming(t, Trust(cfg), home)
}

// A-67: a group-writable home is the most common legitimate layout the walk
// refuses, and the refusal is only defensible if it says how to get out of it.
func TestGroupWritableHomeIsRefusedWithAFix(t *testing.T) {
	home := pathCheckHomeStoreOutside(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	chmodMode(t, home, 0o775)

	err := Trust(cfg)
	assertRefusedNaming(t, err, home)
	if !strings.Contains(err.Error(), "chmod") {
		t.Errorf("got %v, want a refusal telling the user to chmod their home", err)
	}
}

// A-68, A-69: a grant is recognized by existence alone, so what counts as one
// has to be narrow. A directory or a symlink carrying the right name is not a
// record anyone wrote through Trust, and the directory cannot even be revoked.
func TestOnlyRegularFilesCountAsGrants(t *testing.T) {
	cases := []struct {
		id, name string
		plant    func(t *testing.T, record, decoy string)
	}{
		{id: "A-68", name: "directory", plant: func(t *testing.T, record, decoy string) {
			if err := os.Mkdir(record, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{id: "A-69", name: "symlink", plant: func(t *testing.T, record, decoy string) {
			if err := os.Symlink(decoy, record); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			home := pathCheckHome(t)
			ws := filepath.Join(home, "ws")
			cfg := newWorkspaceAt(t, ws)
			mkdirMode(t, storeDir(t), 0o700)
			decoy := filepath.Join(home, "decoy")
			if err := os.WriteFile(decoy, []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			tc.plant(t, grantFor(t, cfg), decoy)
			if IsTrusted(cfg) {
				t.Error("a store entry that is not a record was taken for a grant")
			}
			if _, _, err := LoadTrustedConfig(cfg); !errors.Is(err, ErrUntrusted) {
				t.Errorf("LoadTrustedConfig: got %v, want ErrUntrusted", err)
			}
		})
	}
}

// A-70: a record that cannot be read may be the very grant being revoked.
// Reporting "not trusted" over it says the approval is gone while it is not.
func TestUntrustRefusesToGuessAtAnUnreadableRecord(t *testing.T) {
	skipIfRoot(t)
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	record := onlyRecord(t)
	chmodMode(t, record, 0o000)

	err := Untrust(cfg)
	if err == nil {
		t.Fatal("Untrust reported success over a record it could not read")
	}
	if strings.HasPrefix(err.Error(), "not trusted:") {
		t.Fatalf("unreadable record reported as not trusted: %v", err)
	}
	if !IsTrusted(cfg) {
		t.Error("the grant is gone, so the refusal was about something else")
	}
}

// A-71: the payload is what untrust matches on. A record naming a different
// config is left alone, which is what this pins: matching on the file name
// instead would revoke by fingerprint and leave edited-away grants behind.
func TestUntrustLeavesRecordsNamingAnotherConfig(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	record := onlyRecord(t)
	if err := os.WriteFile(record, []byte(filepath.Join(home, "elsewhere", ConfigFileName)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Untrust(cfg)
	if err == nil || !strings.HasPrefix(err.Error(), "not trusted:") {
		t.Errorf("got %v, want a not-trusted verdict for a record naming another config", err)
	}
	if _, statErr := os.Stat(record); statErr != nil {
		t.Errorf("the record naming another config was removed: %v", statErr)
	}
}

// A-72, A-73, A-108: an interrupted write must not pass as an approval. The
// leftovers it leaves are prune's to clean up, and untrust's to ignore.
func TestInterruptedGrantWritesNeverCountAsApproval(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	mkdirMode(t, storeDir(t), 0o700)
	id, err := configIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	record := grantFor(t, cfg)
	// What a Trust killed between the write and the rename leaves behind, and
	// what one killed before the write finished leaves behind.
	if err := os.WriteFile(record+".tmp", []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeDir(t), "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if IsTrusted(cfg) {
		t.Error("a .tmp leftover was taken for a grant")
	}
	if _, _, err := LoadTrustedConfig(cfg); !errors.Is(err, ErrUntrusted) {
		t.Errorf("LoadTrustedConfig: got %v, want ErrUntrusted", err)
	}
	if err := Untrust(cfg); err == nil || !strings.HasPrefix(err.Error(), "not trusted:") {
		t.Errorf("Untrust: got %v, want a not-trusted verdict", err)
	}
	if _, err := os.Stat(record + ".tmp"); err != nil {
		t.Errorf("Untrust consumed the leftover as a grant: %v", err)
	}
	if err := Prune(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries after prune, want the leftovers gone", len(entries))
	}
}

// A-74: revocation walks the whole store. An optimization that stops early
// leaves a live grant behind while reporting success.
func TestUntrustFindsARecordAmongManyThousands(t *testing.T) {
	if testing.Short() {
		t.Skip("writes ten thousand records")
	}
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	store := storeDir(t)
	for i := 0; i < 10000; i++ {
		name := fmt.Sprintf("%064x", i)
		body := filepath.Join(home, "other", fmt.Sprint(i), ConfigFileName)
		if err := os.WriteFile(filepath.Join(store, name), []byte(body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := Untrust(cfg); err != nil {
		t.Fatalf("untrust across a large store failed: %v", err)
	}
	if IsTrusted(cfg) {
		t.Error("the grant survived an untrust that reported success")
	}
	if err := Prune(); err != nil {
		t.Fatalf("prune across a large store failed: %v", err)
	}
}

// A-75: approving twice is not an error and leaves one record, which is what
// writing through a rename is for.
func TestTrustIsIdempotent(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))

	for i := 0; i < 2; i++ {
		if err := Trust(cfg); err != nil {
			t.Fatalf("Trust %d failed: %v", i+1, err)
		}
	}
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d records after approving twice, want 1", len(entries))
	}
}

// A-76, A-77: an edit leaves the previous bytes' record on disk. Revoking by
// the current fingerprint would leave it there, and restoring the old content
// would bring the approval back with it.
func TestUntrustRemovesEveryGrantForTheConfig(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, ws, `{"env": {"FOO": "edited"}}`)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d records after two approvals, want 2", len(entries))
	}

	if err := Untrust(cfg); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d records after one untrust, want none", len(entries))
	}
	writeConfig(t, ws, pathCheckConfig)
	if IsTrusted(cfg) {
		t.Error("restoring the original bytes revived a revoked approval")
	}
}

// A-78: revocation has to answer to the same identity approval does, or a
// workspace entered through a symlink cannot be revoked from where it was
// approved.
func TestUntrustThroughAnAliasPath(t *testing.T) {
	home := pathCheckHome(t)
	real := filepath.Join(home, "real")
	ws := filepath.Join(real, "proj")
	cfg := newWorkspaceAt(t, ws)
	alias := filepath.Join(home, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}

	if err := Untrust(filepath.Join(alias, "proj", ConfigFileName)); err != nil {
		t.Fatalf("untrust through the alias failed: %v", err)
	}
	if IsTrusted(cfg) {
		t.Error("the grant survived an untrust through the alias")
	}
}

// A-79: mid-rebuild the target of a deployed config is briefly gone while the
// link, which is what the identity names, is still there. Prune has no evidence
// the config was removed and must keep the record.
func TestPruneKeepsAGrantForADanglingConfigSymlink(t *testing.T) {
	home := pathCheckHome(t)
	target := filepath.Join(home, "store-1", "config")
	cfg := symlinkConfig(t, filepath.Join(home, "ws"), target, pathCheckConfig)
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
	if len(entries) != 1 {
		t.Errorf("got %d records after pruning over a dangling config symlink, want 1", len(entries))
	}
}

// A-80: a config that cannot be statted is not a config that is gone. Pruning
// on that guess revokes a live approval, and the user finds out at the next
// prompt that refuses to apply.
func TestPruneKeepsAndReportsWhatItCannotStat(t *testing.T) {
	skipIfRoot(t)
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	chmodMode(t, ws, 0o000)

	var pruneErr error
	output := capturedProgress(t, func() { pruneErr = Prune() })
	if pruneErr != nil {
		t.Fatal(pruneErr)
	}
	if !strings.Contains(output, ws) {
		t.Errorf("prune said %q, want a warning naming %s", output, ws)
	}
	chmodMode(t, ws, 0o755)
	if !IsTrusted(cfg) {
		t.Error("prune revoked a grant whose config it could not stat")
	}
}

// swapConfig replaces the file at path with different content and mode, through
// a rename, which is how a swap in a writable directory actually happens.
func swapConfig(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	tmp := path + ".swap"
	if err := os.WriteFile(tmp, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmp, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// A-81: between the checks and the read there is a window. However it is
// closed, the bytes a grant covers have to be bytes that passed the checks:
// otherwise the approval vouches for content the human never saw.
func TestTrustNeverGrantsBytesThatSkippedTheChecks(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	const swapped = `{"env": {"FOO": "theirs"}}`

	var once sync.Once
	openConfigFile = func(path string) (*os.File, error) {
		f, err := os.Open(path)
		once.Do(func() { swapConfig(t, cfg, swapped, 0o666) })
		return f, err
	}
	t.Cleanup(func() { openConfigFile = openConfigFileDefault })

	err := Trust(cfg)
	openConfigFile = openConfigFileDefault
	id, idErr := configIdentity(cfg)
	if idErr != nil {
		t.Fatal(idErr)
	}
	forged := filepath.Join(storeDir(t), fingerprintBytes(id, []byte(swapped)))
	if _, statErr := os.Stat(forged); statErr == nil {
		t.Errorf("Trust (returning %v) approved bytes swapped in after the checks", err)
	}
}

// A-82: the fingerprint and the parse have to come off one read. Reading twice
// puts a window between what was approved and what is applied.
func TestLoadTrustedConfigReadsTheConfigOnce(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}

	reads := 0
	openConfigFile = func(path string) (*os.File, error) {
		reads++
		return openConfigFileDefault(path)
	}
	t.Cleanup(func() { openConfigFile = openConfigFileDefault })

	if _, _, err := LoadTrustedConfig(cfg); err != nil {
		t.Fatal(err)
	}
	openConfigFile = openConfigFileDefault
	if reads != 1 {
		t.Errorf("LoadTrustedConfig read the config %d times, want exactly 1", reads)
	}
}

// A-83: the window between checking the store and using a grant cannot be
// closed entirely. The next prompt is where it has to be caught, since the hook
// runs on every one of them.
func TestExportStopsApplyingOnceTheStoreTurnsWritable(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	enter := mustBuild(t, ws, false)
	if !strings.Contains(enter, "FOO=") {
		t.Fatalf("the workspace was never applied:\n%s", enter)
	}
	setState(t, stateFromScript(t, enter))
	chmodMode(t, storeDir(t), 0o777)

	res, err := BuildExportScript(ws, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Script, "unset FOO") {
		t.Errorf("the applied workspace was not rolled back:\n%s", res.Script)
	}
	if len(res.Warnings) == 0 {
		t.Error("the environment changed under the user without a word")
	}
}

// A-84: the hook runs on every prompt, so a read that blocks takes the shell
// with it. FindRoot's regular-file check happens before the open, and the file
// can become a fifo in between.
func TestConfigReadDoesNotBlockWhenTheFileTurnsIntoAFifo(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}

	var once sync.Once
	openConfigFile = func(path string) (*os.File, error) {
		once.Do(func() {
			if err := os.Remove(cfg); err != nil {
				return
			}
			_ = syscall.Mkfifo(cfg, 0o644)
		})
		return openConfigFileDefault(path)
	}
	t.Cleanup(func() { openConfigFile = openConfigFileDefault })

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = BuildExportScript(ws, true)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Give the blocked open a writer so the goroutine can finish; without it
		// the run leaks a thread parked in the kernel.
		if f, err := os.OpenFile(cfg, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		<-done
		t.Error("the read blocked on a fifo swapped in for the config; the prompt hangs here")
	}
	openConfigFile = openConfigFileDefault
}

// A-85: the size limit exists to bound what every prompt pays. Deciding it from
// the stat alone leaves it to whatever the file became by the time it is read.
func TestConfigReadStopsAtTheSizeLimitWhenTheFileGrows(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)

	var once sync.Once
	openConfigFile = func(path string) (*os.File, error) {
		once.Do(func() { writeConfigOfSize(t, ws, maxConfigSize+1) })
		return openConfigFileDefault(path)
	}
	t.Cleanup(func() { openConfigFile = openConfigFileDefault })

	_, err := LoadConfig(cfg)
	openConfigFile = openConfigFileDefault
	if err == nil {
		t.Error("a config that grew past the limit inside the read window was accepted whole")
	}
}

// A-86: two shells operating on the same store is ordinary use. Neither command
// may report a result that is not what happened.
func TestConcurrentTrustAndUntrustReportTruthfully(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				errs <- Trust(cfg)
				return
			}
			errs <- Untrust(cfg)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil || strings.HasPrefix(err.Error(), "not trusted:") {
			continue
		}
		t.Errorf("a concurrent trust/untrust failed with %v", err)
	}
	entries, err := os.ReadDir(storeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a half-written record was left behind: %s", e.Name())
		}
	}
}

// A-87: the Nix shape, which is the first thing a stricter walk breaks: a
// user-owned link into a store directory nobody but root writes, under a
// group-writable sticky /nix/store.
func TestTrustAcceptsTheNixLayout(t *testing.T) {
	home := pathCheckHome(t)
	nix := filepath.Join(home, "nix")
	mkdirMode(t, nix, 0o755)
	store := filepath.Join(nix, "store")
	mkdirMode(t, store, 0o775|os.ModeSticky)
	gen := filepath.Join(store, "hash-sallyport-config")
	mkdirMode(t, gen, 0o755)
	target := filepath.Join(gen, ConfigFileName)
	if err := os.WriteFile(target, []byte(pathCheckConfig), 0o444); err != nil {
		t.Fatal(err)
	}
	chmodMode(t, gen, 0o555)
	ws := filepath.Join(home, "ws")
	mkdirMode(t, ws, 0o755)
	cfg := ConfigPath(ws)
	if err := os.Symlink(target, cfg); err != nil {
		t.Fatal(err)
	}

	if err := Trust(cfg); err != nil {
		t.Fatalf("refused the Nix layout: %v", err)
	}
	if _, _, err := LoadTrustedConfig(cfg); err != nil {
		t.Errorf("the Nix layout is approved but not applied: %v", err)
	}
}

// A-88: home-manager reaches the deployed file through its gcroots, five to
// eight links deep. Refusing chains outright, or capping them low, breaks every
// home-manager user.
func TestTrustAcceptsTheHomeManagerLayout(t *testing.T) {
	home := pathCheckHome(t)
	gcroots := filepath.Join(home, ".local", "state", "home-manager", "gcroots")
	mkdirMode(t, gcroots, 0o755)
	generation := filepath.Join(home, "nix", "store", "hash-home-manager-generation", "home-files")
	mkdirMode(t, generation, 0o755)
	target := filepath.Join(generation, ConfigFileName)
	if err := os.WriteFile(target, []byte(pathCheckConfig), 0o444); err != nil {
		t.Fatal(err)
	}
	chmodMode(t, generation, 0o555)
	cfg := filepath.Join(home, ConfigFileName)
	nodes := symlinkChain(t, gcroots, cfg, target, 5)

	if err := Trust(nodes[0]); err != nil {
		t.Fatalf("refused the home-manager layout: %v", err)
	}
	if !IsTrusted(cfg) {
		t.Error("the home-manager layout is not trusted after Trust")
	}
}

// A-89: a config an administrator hands out under /opt is root-owned all the
// way down, and the user's own store is elsewhere.
func TestTrustAcceptsARootOwnedSharedConfig(t *testing.T) {
	home := pathCheckHomeStoreOutside(t)
	opt := filepath.Join(filepath.Dir(home), "opt")
	team := filepath.Join(opt, "team", "proj")
	cfg := newWorkspaceAt(t, team)
	for _, dir := range []string{team, filepath.Dir(team), opt} {
		chownTo(t, dir, 0)
	}
	chownTo(t, cfg, 0)

	if err := Trust(cfg); err != nil {
		t.Fatalf("refused a root-owned shared config: %v", err)
	}
}

// A-90, A-100: the two layouts the walk refuses that nobody set up to be
// dangerous. Both are the right verdict — a group member can rename the config
// out from under the approval — and both are only survivable if the refusal
// says what to run.
func TestGroupWritableLayoutsAreRefusedWithAFix(t *testing.T) {
	cases := []struct {
		id, name string
		// arrange returns the node the refusal must name.
		arrange func(t *testing.T, ws, cfg string) string
	}{
		{id: "A-90", name: "shared project tree", arrange: func(t *testing.T, ws, cfg string) string {
			chmodMode(t, ws, 0o775)
			return ws
		}},
		{id: "A-100", name: "umask 002 user-private group", arrange: func(t *testing.T, ws, cfg string) string {
			chmodMode(t, cfg, 0o664)
			chmodMode(t, ws, 0o775)
			return cfg
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			home := pathCheckHome(t)
			ws := filepath.Join(home, "srv", "shared", "proj")
			cfg := newWorkspaceAt(t, ws)

			node := tc.arrange(t, ws, cfg)
			err := Trust(cfg)
			assertRefusedNaming(t, err, node)
			if !strings.Contains(err.Error(), "chmod") {
				t.Errorf("got %v, want a refusal telling the user what to run", err)
			}
		})
	}
}

// A-90: the escape hatch the refusal points at has to exist.
func TestPathCheckOptOutApprovesARefusedLayout(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "shared")
	cfg := newWorkspaceAt(t, ws)
	chmodMode(t, ws, 0o775)
	if err := Trust(cfg); err == nil {
		t.Fatal("the layout is not refused, so the opt-out proves nothing")
	}

	t.Setenv(pathCheckOptOut, "1")
	if err := Trust(cfg); err != nil {
		t.Fatalf("%s=1 did not lift the refusal: %v", pathCheckOptOut, err)
	}
	if !IsTrusted(cfg) {
		t.Errorf("%s=1 approved a config the lookup then ignores", pathCheckOptOut)
	}
}

// A-91: a throwaway workspace under /tmp, which is world-writable, sticky, and
// reached through a symlink on macOS. One approval covers both spellings.
func TestTrustAcceptsAWorkspaceUnderAStickyTmp(t *testing.T) {
	home := pathCheckHome(t)
	tmp := filepath.Join(home, "tmp")
	mkdirMode(t, tmp, 0o777|os.ModeSticky)
	ws := filepath.Join(tmp, "proj")
	cfg := newWorkspaceAt(t, ws)
	alias := filepath.Join(home, "alias-tmp")
	if err := os.Symlink(tmp, alias); err != nil {
		t.Fatal(err)
	}

	if err := Trust(filepath.Join(alias, "proj", ConfigFileName)); err != nil {
		t.Fatalf("refused a workspace under a sticky world-writable directory: %v", err)
	}
	if !IsTrusted(cfg) {
		t.Error("the grant taken through /tmp's alias does not cover the real path")
	}
}

// A-92: a checkout that lives on another volume and is reached through a
// symlink in the home directory. The identity has to settle on the resolved
// location so it survives.
func TestTrustAcceptsASymlinkedCheckout(t *testing.T) {
	home := pathCheckHome(t)
	volume := filepath.Join(home, "volumes", "ext", "w")
	cfg := newWorkspaceAt(t, volume)
	link := filepath.Join(home, "w")
	if err := os.Symlink(volume, link); err != nil {
		t.Fatal(err)
	}

	if err := Trust(link + "/" + ConfigFileName); err != nil {
		t.Fatalf("refused a symlinked checkout: %v", err)
	}
	id, err := configIdentity(link + "/" + ConfigFileName)
	if err != nil {
		t.Fatal(err)
	}
	if id != cfg {
		t.Errorf("identity = %q, want the resolved location %q", id, cfg)
	}
}

// A-95: the store and its records carry modes sallyport asks for explicitly, so
// a permissive umask must not widen them and a strict one must not be needed.
func TestStoreAndRecordModesIgnoreTheUmask(t *testing.T) {
	for _, mask := range []int{0o077, 0o022, 0o000} {
		t.Run(fmt.Sprintf("%04o", mask), func(t *testing.T) {
			home := pathCheckHome(t)
			ws := filepath.Join(home, "ws")
			mkdirMode(t, ws, 0o755)
			// Set after every directory the layout needs: t.TempDir and MkdirAll
			// leave the narrowing to the umask, so a tree built under 0000 comes
			// out world-writable and is refused for that instead.
			old := syscall.Umask(mask)
			t.Cleanup(func() { syscall.Umask(old) })

			if err := Create(ws); err != nil {
				t.Fatalf("Create failed under umask %04o: %v", mask, err)
			}
			fi, err := os.Stat(storeDir(t))
			if err != nil {
				t.Fatal(err)
			}
			if perm := fi.Mode().Perm(); perm != 0o700 {
				t.Errorf("store mode %04o under umask %04o, want 0700", perm, mask)
			}
			ri, err := os.Stat(onlyRecord(t))
			if err != nil {
				t.Fatal(err)
			}
			if perm := ri.Mode().Perm(); perm != 0o600 {
				t.Errorf("record mode %04o under umask %04o, want 0600", perm, mask)
			}
		})
	}
}

// setfaclOrSkip runs setfacl, skipping where POSIX ACLs are not available.
func setfaclOrSkip(t *testing.T, args ...string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("POSIX ACLs are a Linux arrangement")
	}
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("setfacl not available")
	}
	if out, err := exec.Command("setfacl", args...).CombinedOutput(); err != nil {
		t.Skipf("setfacl %v: %v\n%s", args, err, out)
	}
}

// A-97: adding an ACL entry raises the group bits to the mask, so a check that
// reads only the mode bits refuses this by accident rather than by design. The
// accident is load-bearing: pinning it here means a rewrite that drops the mode
// check in favour of ownership alone shows up as a failure.
func TestAclGrantOnTheWorkspaceIsRefusedThroughTheGroupBits(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	setfaclOrSkip(t, "-m", fmt.Sprintf("u:%d:rwx", foreignUID()), ws)

	assertRefusedNaming(t, Trust(cfg), ws)
}

// A-99: a default ACL on the directory the store is created in decides the mode
// the store comes out with. Whatever that mode turns out to be, the verdict on
// it has to be the same one every entry point reaches, or the user is told the
// store they just created is unsafe by one command and fine by the next.
func TestStoreCreatedUnderADefaultAclIsJudgedConsistently(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	data := filepath.Join(home, "data")
	mkdirMode(t, data, 0o755)
	setfaclOrSkip(t, "-d", "-m", "g::rwx", data)
	t.Setenv("XDG_DATA_HOME", data)

	err := Trust(cfg)
	if err == nil {
		if !IsTrusted(cfg) {
			t.Error("Trust reported success into a store the lookup then refuses")
		}
		return
	}
	assertRefusedNaming(t, err, storeDir(t))
}

// A-101: IsTrusted and LoadTrustedConfig answer the same question and are used
// by different callers. A path check added to one of them only is the shape
// this has taken before.
func TestGrantLookupAndApplyAgreeOnUnsafeLayouts(t *testing.T) {
	cases := []struct {
		id, name string
		arrange  func(t *testing.T, home, ws string)
	}{
		{id: "A-11", name: "writable ancestor", arrange: func(t *testing.T, home, ws string) {
			chmodMode(t, filepath.Dir(ws), 0o777)
		}},
		{id: "A-52", name: "writable store parent", arrange: func(t *testing.T, home, ws string) {
			chmodMode(t, filepath.Dir(storeDir(t)), 0o777)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			home := pathCheckHome(t)
			ws := filepath.Join(home, "outer", "ws")
			cfg := newWorkspaceAt(t, ws)
			if err := Trust(cfg); err != nil {
				t.Fatal(err)
			}
			tc.arrange(t, home, ws)

			trusted := IsTrusted(cfg)
			_, _, err := LoadTrustedConfig(cfg)
			if trusted {
				t.Error("IsTrusted still vouches for the config")
			}
			if err == nil {
				t.Error("LoadTrustedConfig applied the config")
			}
		})
	}
}

// A-102, A-103: when the store goes bad while a workspace is applied, the
// environment is rolled back. Doing that silently leaves the user with an
// environment that changed for no reason they can see, so the precmd call has
// to speak up even though it is the quiet one.
func TestRollbackFromAnUnsafeStoreAlwaysWarns(t *testing.T) {
	for _, quiet := range []bool{false, true} {
		t.Run(fmt.Sprintf("quiet=%v", quiet), func(t *testing.T) {
			home := pathCheckHome(t)
			ws := filepath.Join(home, "ws")
			cfg := newWorkspaceAt(t, ws)
			if err := Trust(cfg); err != nil {
				t.Fatal(err)
			}
			enter := mustBuild(t, ws, false)
			setState(t, stateFromScript(t, enter))
			chmodMode(t, storeDir(t), 0o770)

			res, err := BuildExportScript(ws, quiet)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(res.Script, "unset FOO") {
				t.Errorf("the applied workspace was not rolled back:\n%s", res.Script)
			}
			if !hasWarning(res.Warnings, storeDir(t)) {
				t.Errorf("got warnings %q, want one naming the store", res.Warnings)
			}
		})
	}
}

// A-105: a directory named .sallyport.jsonc is not a config. Taking it for one
// stops the search at a workspace that does not exist; skipping it silently
// approves a different config than the one the user is standing in.
func TestFindRootSkipsADirectoryNamedLikeTheConfig(t *testing.T) {
	home := pathCheckHome(t)
	outer := filepath.Join(home, "outer")
	mkdirMode(t, outer, 0o755)
	writeConfig(t, outer, pathCheckConfig)
	inner := filepath.Join(outer, "inner")
	mkdirMode(t, filepath.Join(inner, ConfigFileName), 0o755)

	if got := FindRoot(inner); got != outer {
		t.Errorf("FindRoot = %q, want the workspace above the decoy, %q", got, outer)
	}
}

// A-106: no store is the state every user starts in. Both commands have to
// treat it as "nothing approved" rather than as a failure to look.
func TestUntrustAndPruneWithoutAStore(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))

	err := Untrust(cfg)
	if err == nil || !strings.HasPrefix(err.Error(), "not trusted:") {
		t.Errorf("Untrust: got %v, want a not-trusted verdict", err)
	}
	output := capturedProgress(t, func() {
		if err := Prune(); err != nil {
			t.Errorf("Prune failed with no store: %v", err)
		}
	})
	if !strings.Contains(output, "prune") {
		t.Errorf("prune said %q, want it to report there was nothing to do", output)
	}
}

// A-107: a store that cannot be written to fails at the point of writing, and
// the raw errno on its own does not say which directory the user has to fix.
func TestTrustReportsAStoreItCannotCreate(t *testing.T) {
	skipIfRoot(t)
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	data := filepath.Join(home, "data")
	mkdirMode(t, data, 0o500)
	t.Setenv("XDG_DATA_HOME", data)

	err := Trust(cfg)
	if err == nil {
		t.Fatal("Trust reported success without a store to write to")
	}
	if !mentions(err, data) && !mentions(err, storeDir(t)) {
		t.Errorf("got %v, want an error naming the store it could not create", err)
	}
	if IsTrusted(cfg) {
		t.Error("a config is trusted although no grant could be written")
	}
}

// A-109: a directory name is not always well behaved. A record is the identity
// plus a newline and untrust compares it after trimming, so an identity ending
// in whitespace would match nothing and leave a grant that cannot be revoked.
func TestHostileWorkspaceNamesCanStillBeRevoked(t *testing.T) {
	names := map[string]string{
		"newline":        "ws\nx",
		"trailing space": "ws ",
		"non-utf8":       "ws\xff",
	}
	for name, dir := range names {
		t.Run(name, func(t *testing.T) {
			home := pathCheckHome(t)
			ws := filepath.Join(home, dir)
			if err := os.Mkdir(ws, 0o755); err != nil {
				t.Skipf("the filesystem refuses this name: %v", err)
			}
			writeConfig(t, ws, pathCheckConfig)
			cfg := ConfigPath(ws)

			if err := Trust(cfg); err != nil {
				t.Fatalf("Trust failed: %v", err)
			}
			if err := Untrust(cfg); err != nil {
				t.Fatalf("a grant taken on %q cannot be revoked: %v", dir, err)
			}
			if IsTrusted(cfg) {
				t.Error("the grant survived an untrust that reported success")
			}
		})
	}
}

// A-111: WORKSPACE_PATH is always emitted literally, so quoting is the only
// thing standing between a directory name and the shell acting on it. The name
// is not something the user picks on purpose.
func TestWorkspacePathSurvivesZshWithHostileDirectoryNames(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	names := map[string]string{
		"apostrophe": "o'brien",
		"space":      "a b",
		"dollar":     "x$y",
		"newline":    "two\nlines",
	}
	for name, dir := range names {
		t.Run(name, func(t *testing.T) {
			t.Setenv(stateEnvKey, "")
			_ = os.Unsetenv("WORKSPACE_PATH")
			root := exportUntrustedWorkspaceDirNamed(t, dir, pathCheckConfig)
			if err := Trust(ConfigPath(root)); err != nil {
				t.Fatal(err)
			}

			got := exportRunZsh(t, zsh, root, mustBuild(t, root, false)+`
printf 'WS=[%s]\n' "$WORKSPACE_PATH"
`)
			if !strings.Contains(got, "WS=["+root+"]") {
				t.Errorf("zsh output does not carry the workspace path verbatim:\n%s", got)
			}
			if _, err := os.Stat(filepath.Join(root, "OOPS")); err == nil {
				t.Error("the path was executed as a command instead of being applied as text")
			}
		})
	}
}

// A-112: the size limit is about what gets read, and through a symlink that is
// the target. Judging the link's own stat measures the length of the target's
// name instead.
func TestSizeLimitAppliesToASymlinkTarget(t *testing.T) {
	home := pathCheckHome(t)
	targetDir := filepath.Join(home, "store")
	mkdirMode(t, targetDir, 0o755)
	writeConfigOfSize(t, targetDir, maxConfigSize+1)
	ws := filepath.Join(home, "ws")
	mkdirMode(t, ws, 0o755)
	cfg := ConfigPath(ws)
	if err := os.Symlink(ConfigPath(targetDir), cfg); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadConfig(cfg); err == nil {
		t.Error("a config over the size limit was read through a symlink")
	}
	if err := Trust(cfg); err == nil {
		t.Error("Trust approved a config over the size limit")
	}
}

// The cases below come from the survey of the nine comparable tools rather than
// from the case list, and are marked P-n for that reason.

// P-1, P-2: the rule is about who can write, not who can read, and it is applied
// to the file whatever its directory allows. OpenSSH refuses a writable file
// outright while GnuPG lets a private enclosing directory excuse it; this pins
// sallyport on OpenSSH's side of that split.
func TestConfigFileModesFollowTheWritableRuleOnly(t *testing.T) {
	cases := []struct {
		id, name string
		cfgMode  os.FileMode
		dirMode  os.FileMode
		accept   bool
	}{
		{id: "P-1", name: "read-only config", cfgMode: 0o444, dirMode: 0o755, accept: true},
		{id: "P-1", name: "group-readable config", cfgMode: 0o644, dirMode: 0o755, accept: true},
		{id: "P-2", name: "writable config in a private directory", cfgMode: 0o666, dirMode: 0o700},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			home := pathCheckHome(t)
			ws := filepath.Join(home, "ws")
			cfg := newWorkspaceAt(t, ws)
			chmodMode(t, cfg, tc.cfgMode)
			chmodMode(t, ws, tc.dirMode)

			err := Trust(cfg)
			if tc.accept {
				if err != nil {
					t.Fatalf("refused a config at mode %04o in a %04o directory: %v", tc.cfgMode, tc.dirMode, err)
				}
				return
			}
			assertRefusedNaming(t, err, cfg)
		})
	}
}

// P-3: the walk stops at HOME, so what sits above it is not examined. /home is
// group-writable on Ubuntu and on any site that uses USERGROUPS_ENAB, and a
// walk that runs to / refuses every user there. Stopping is not a gap: whoever
// can write the directory above a home can replace the shell rc that starts
// sallyport in the first place.
func TestNothingAboveHomeTakesPartInTheVerdict(t *testing.T) {
	base := pathCheckBase(t)
	home := filepath.Join(base, "home")
	mkdirMode(t, home, 0o755)
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	chmodMode(t, base, 0o777)

	if err := Trust(cfg); err != nil {
		t.Fatalf("a directory above HOME decided the verdict: %v", err)
	}
	if !IsTrusted(cfg) {
		t.Error("config not trusted after Trust")
	}
}

// P-4: root ownership is accepted because only root can undo it, which says
// nothing about the mode. A root-owned file the admin group can write is
// exactly the /usr/local shape, and the mode rule applies to it unchanged.
func TestRootOwnershipDoesNotExemptTheModeRule(t *testing.T) {
	cases := []struct {
		id, name string
		mode     os.FileMode
		accept   bool
	}{
		{id: "P-4", name: "root-owned config in the user's own directory", mode: 0o644, accept: true},
		{id: "P-4", name: "root-owned group-writable config", mode: 0o664},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			home := pathCheckHome(t)
			cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
			chmodMode(t, cfg, tc.mode)
			chownTo(t, cfg, 0)

			err := Trust(cfg)
			if tc.accept {
				if err != nil {
					t.Fatalf("refused a root-owned config at mode %04o: %v", tc.mode, err)
				}
				return
			}
			assertRefusedNaming(t, err, cfg)
		})
	}
}

// P-5: the approval covers a config at a location, so the same bytes somewhere
// else are a different config. Copying an approved file into a second checkout
// must not carry the approval with it.
func TestApprovalDoesNotFollowACopiedConfig(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(home, "second")
	mkdirMode(t, elsewhere, 0o755)
	content, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ConfigPath(elsewhere), content, 0o644); err != nil {
		t.Fatal(err)
	}

	if IsTrusted(ConfigPath(elsewhere)) {
		t.Error("the approval followed the bytes into a second location")
	}
}

// P-6: a store that is private now may not always have been. A record another
// user owns is a leftover of the window when it was not, and it is the one
// record in the store that cannot have been written by its owner.
func TestGrantOwnedByAnotherUserDoesNotCount(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	chownTo(t, onlyRecord(t), foreignUID())

	if IsTrusted(cfg) {
		t.Error("a record another user owns was honored as a grant")
	}
	if _, _, err := LoadTrustedConfig(cfg); err == nil {
		t.Error("a config was applied on a record another user owns")
	}
}
