package workspace

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// B-55: the search must not stop at a depth somebody picked. The tree is built
// one level at a time so the run reaches whatever this platform's path limit
// allows -- around 400 on macOS, past 1000 on Linux -- and the deepest level
// actually reached is asserted rather than assumed.
func TestFindRootHasNoDepthLimit(t *testing.T) {
	base := bIsolatedTree(t)
	writeConfig(t, base, `{"env": {}}`)

	const want = 1000
	dirs := []string{base}
	dir := base
	for i := 0; i < want; i++ {
		next := filepath.Join(dir, "a")
		if err := os.Mkdir(next, 0o755); err != nil {
			t.Logf("this platform stops at depth %d: %v", i, err)
			break
		}
		dir = next
		dirs = append(dirs, dir)
	}
	deepest := len(dirs) - 1
	if deepest < 100 {
		t.Fatalf("only %d levels could be created; the case needs at least 100", deepest)
	}
	t.Logf("deepest level built: %d (path is %d bytes)", deepest, len(dirs[deepest]))

	depths := []int{0, 1, 5, 20, 100, deepest}
	for _, d := range depths {
		if d > deepest {
			continue
		}
		if got := FindRoot(dirs[d]); got != base {
			t.Errorf("depth %d: FindRoot = %q, want %q", d, got, base)
		}
	}
}

// B-56: with nothing to find, the climb has to end at the filesystem root and
// answer "no workspace" rather than loop.
func TestFindRootTerminatesWithNothingToFind(t *testing.T) {
	dir := bIsolatedTree(t)
	nested := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() { done <- FindRoot(nested) }()
	select {
	case got := <-done:
		if got != "" {
			t.Errorf("FindRoot = %q, want empty", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("FindRoot did not terminate")
	}
}

// B-57: the topmost directory is checked before the climb gives up, so a config
// at the filesystem root is found. It needs a root nobody shares, so it runs
// only where one has been prepared: a throwaway container that sets
// SALLYPORT_TEST_ROOT_CONFIG=1 after writing /.sallyport.jsonc.
func TestFindRootFindsConfigAtFilesystemRoot(t *testing.T) {
	if os.Getenv("SALLYPORT_TEST_ROOT_CONFIG") != "1" {
		t.Skip("needs a disposable filesystem root; set SALLYPORT_TEST_ROOT_CONFIG=1 with /" + ConfigFileName + " in place")
	}
	if _, err := os.Stat("/" + ConfigFileName); err != nil {
		t.Fatalf("SALLYPORT_TEST_ROOT_CONFIG is set but /%s is missing: %v", ConfigFileName, err)
	}
	for _, start := range []string{"/", "/tmp", "/usr/share"} {
		if _, err := os.Stat(start); err != nil {
			continue
		}
		if got := FindRoot(start); got != "/" {
			t.Errorf("FindRoot(%q) = %q, want \"/\"", start, got)
		}
	}
}

// B-58: callers pass an absolute path (os.Getwd, or a canonicalised pwd). A
// relative one silently reinterprets the search against whatever the process
// cwd happens to be, so scope.md has it refused rather than answered.
//
// Refusal is asserted as "names no root". scope.md asks for an error, which
// FindRoot cannot return with its current one-value signature; changing that is
// implementation work this case does not do.
func TestFindRootRefusesRelativeInput(t *testing.T) {
	base := bIsolatedTree(t)
	sub := filepath.Join(base, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, sub, `{"env": {}}`)

	t.Chdir(base)
	for _, rel := range []string{"sub", "./sub", "sub/", "."} {
		if got := FindRoot(rel); got != "" {
			t.Errorf("FindRoot(%q) = %q; a relative start must not name a root", rel, got)
		}
	}

	t.Chdir(sub)
	for _, rel := range []string{".", "./", "../sub"} {
		if got := FindRoot(rel); got != "" {
			t.Errorf("from inside the workspace, FindRoot(%q) = %q; a relative start must not name a root", rel, got)
		}
	}
}

// B-59: filepath.Clean("") is ".", so an empty argument today searches the
// process cwd. Same reasoning as B-58: refuse it rather than let a caller's bug
// turn into a search somewhere else.
func TestFindRootRefusesEmptyInput(t *testing.T) {
	base := bIsolatedTree(t)
	writeConfig(t, base, `{"env": {}}`)
	t.Chdir(base)
	if got := FindRoot(""); got != "" {
		t.Errorf("FindRoot(\"\") = %q; an empty start must not name a root", got)
	}
}

// B-60: `..` after a symlink means something different to the kernel than to
// filepath.Clean, which drops the pair lexically. Resolving before the search
// is what keeps `trust` and the hook talking about the same workspace, whichever
// way the user cd'd in.
func TestFindRootResolvesDotDotThroughSymlinks(t *testing.T) {
	base := bIsolatedTree(t)
	real := filepath.Join(base, "real")
	sub := filepath.Join(real, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, real, `{"env": {}}`)
	link := filepath.Join(base, "link")
	if err := os.Symlink(sub, link); err != nil {
		t.Fatal(err)
	}

	t.Setenv("XDG_DATA_HOME", t.TempDir())
	if err := Trust(ConfigPath(real)); err != nil {
		t.Fatal(err)
	}

	// Both starts land on real once the kernel does the resolving: the link
	// leads into real/sub, and the kernel reads link/.. as real, where Clean
	// reads it as base.
	starts := map[string]string{
		"through the link": link,
		// Concatenated, since filepath.Join would cancel the ".." before
		// FindRoot ever sees it.
		"through the link and up": link + "/..",
	}
	for name, start := range starts {
		t.Run(name, func(t *testing.T) {
			got := FindRoot(start)
			if got != real {
				t.Errorf("FindRoot(%q) = %q, want %q", start, got, real)
			}

			// The hook resolves the directory before searching and `trust` does
			// not, so the two can disagree about which workspace the user is in.
			t.Setenv(stateEnvKey, "")
			res, err := BuildExportScript(start, false)
			if err != nil {
				t.Fatal(err)
			}
			exported := ""
			if res.Script != "" {
				exported = stateFromScript(t, res.Script).Root
			}
			if exported != got {
				t.Errorf("the hook applied %q while FindRoot, which `trust` uses, chose %q", exported, got)
			}
		})
	}
}

// B-61: an ancestor the process cannot traverse hides whatever config sits
// under it. Treating that as "no config here" and carrying on adopts a config
// further up instead -- environment the user never approved for this directory.
func TestFindRootStopsAtAnUnreadableAncestor(t *testing.T) {
	skipIfRoot(t)
	base := bIsolatedTree(t)
	upper := filepath.Join(base, "upper")
	mid := filepath.Join(upper, "mid")
	proj := filepath.Join(mid, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, upper, `{"env": {"FROM": "upper"}}`)
	if err := os.Chmod(mid, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(mid, 0o755); err != nil {
			t.Error(err)
		}
	})

	if got := FindRoot(proj); got == upper {
		t.Errorf("FindRoot climbed past an ancestor it could not read and took %q; a config hidden by permissions must stop the search, not be skipped", got)
	} else if got != "" {
		t.Errorf("FindRoot = %q, want no root", got)
	}
}

// B-62: scope.md has the search cross mount boundaries -- stopping at one would
// change the answer inside containers and on external volumes. It needs a mount
// to make, so it runs only as root on Linux.
func TestFindRootCrossesMountBoundaries(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux to make a mount")
	}
	base := bIsolatedTree(t)
	writeConfig(t, base, `{"env": {}}`)
	mnt := filepath.Join(base, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := bMountTmpfs(t, mnt); err != nil {
		t.Skipf("cannot mount tmpfs: %v", err)
	}
	inner := filepath.Join(mnt, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(inner); got != base {
		t.Errorf("FindRoot = %q, want %q: the search must cross the mount", got, base)
	}
}

// B-63: Nix and home-manager deploy the config as a symlink into a read-only
// store, so the link has to mark the workspace the same way a plain file does.
func TestFindRootAcceptsSymlinkedConfig(t *testing.T) {
	base := bIsolatedTree(t)
	store := filepath.Join(base, "store")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(store, "config")
	if err := os.WriteFile(target, []byte(`{"env": {}}`), 0o444); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "ws")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, ConfigPath(root)); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(root); got != root {
		t.Errorf("FindRoot = %q, want %q", got, root)
	}
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(nested); got != root {
		t.Errorf("from a subdirectory FindRoot = %q, want %q", got, root)
	}
}

// B-64: on a case-insensitive filesystem -- the APFS default -- Stat answers for
// a differently-cased name, so .Sallyport.jsonc marks a workspace there and not
// on Linux. The split is the filesystem's, and pinning it is what keeps the
// suite from passing on one machine and failing on the other.
func TestFindRootCaseSensitivityFollowsTheFilesystem(t *testing.T) {
	base := bIsolatedTree(t)
	if err := os.WriteFile(filepath.Join(base, ".Sallyport.jsonc"), []byte(`{"env": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := FindRoot(base)
	if bCaseInsensitiveFS(t, base) {
		if got != base {
			t.Errorf("FindRoot = %q, want %q: this filesystem folds case, so the name matches", got, base)
		}
		return
	}
	if got != "" {
		t.Errorf("FindRoot = %q, want empty: this filesystem distinguishes case", got)
	}
}

// B-65: FindRoot climbs to the filesystem root, so a config above the temp
// directory answers searches meant to find nothing, and the failure reads as a
// bug in FindRoot. Every case here declares that boundary through
// bIsolatedTree; this one states it outright and shows the climb really does
// reach ancestors, which is why the declaration is needed.
func TestFindRootTestsDeclareTheirSearchBoundary(t *testing.T) {
	base := bIsolatedTree(t)
	bRequireNoAncestorConfig(t, base)

	ancestor := filepath.Join(base, "ancestor")
	deep := filepath.Join(ancestor, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(deep); got != "" {
		t.Fatalf("FindRoot = %q before any config was planted", got)
	}
	writeConfig(t, ancestor, `{"env": {}}`)
	if got := FindRoot(deep); got != ancestor {
		t.Errorf("FindRoot = %q, want %q: a config four levels up decides the answer", got, ancestor)
	}
}

// B-66: a name past the platform's limit makes Stat fail with ENAMETOOLONG, and
// the search treats that like "nothing here" and carries on. Pinned as it
// behaves, so a later change to distinguish error kinds is a deliberate one.
func TestFindRootTreatsTooLongNamesAsAbsent(t *testing.T) {
	root := bIsolatedTree(t)
	writeConfig(t, root, `{"env": {}}`)
	long := filepath.Join(root, strings.Repeat("x", 300))
	if got := FindRoot(long); got != root {
		t.Errorf("FindRoot = %q, want %q", got, root)
	}
}

// B-67: a symlink that points at itself makes every Stat below it fail with
// ELOOP. The climb has to end anyway.
func TestFindRootTerminatesOnASymlinkLoop(t *testing.T) {
	base := bIsolatedTree(t)
	loop := filepath.Join(base, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() { done <- FindRoot(filepath.Join(loop, "a", "b")) }()
	select {
	case got := <-done:
		if got != "" {
			t.Errorf("FindRoot = %q, want empty", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("FindRoot did not terminate through a symlink loop")
	}
}

// B-68: configs get created and deleted while a shell is sitting in the tree.
// Whichever answer the race produces is fine; a panic is not.
func TestFindRootSurvivesConcurrentConfigChurn(t *testing.T) {
	base := bIsolatedTree(t)
	nested := filepath.Join(base, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	path := ConfigPath(filepath.Join(base, "a"))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.WriteFile(path, []byte(`{"env": {}}`), 0o644)
			_ = os.Remove(path)
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := FindRoot(nested)
		if got != "" && got != filepath.Dir(path) {
			t.Fatalf("FindRoot = %q, want either empty or %q", got, filepath.Dir(path))
		}
	}
	close(stop)
	wg.Wait()
}

// B-68b: nested workspaces resolve to the nearest config, on every path that
// looks one up. Getting this wrong applies a parent's environment inside a child
// that was never approved for it.
func TestNestedWorkspacesUseTheNearestConfig(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := bIsolatedTree(t)
	if c, err := filepath.EvalSymlinks(base); err == nil {
		base = c
	}
	parent := filepath.Join(base, "parent")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, parent, `{"env": {"LEVEL": "parent", "ONLY_PARENT": "p"}}`)
	writeConfig(t, child, `{"env": {"LEVEL": "child", "ONLY_CHILD": "c"}}`)

	deep := filepath.Join(child, "x", "y")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ start, want string }{
		{parent, parent},
		{child, child},
		{deep, child},
	} {
		if got := FindRoot(tc.start); got != tc.want {
			t.Errorf("FindRoot(%q) = %q, want %q", tc.start, got, tc.want)
		}
	}

	if err := Trust(ConfigPath(parent)); err != nil {
		t.Fatal(err)
	}
	if err := Trust(ConfigPath(child)); err != nil {
		t.Fatal(err)
	}
	if err := Untrust(ConfigPath(child)); err != nil {
		t.Fatalf("untrust from the child did not revoke the child's grant: %v", err)
	}
	if !IsTrusted(ConfigPath(parent)) {
		t.Error("untrusting the child revoked the parent's grant too")
	}
	if err := Trust(ConfigPath(child)); err != nil {
		t.Fatal(err)
	}

	enter := mustBuild(t, deep, false)
	if !strings.Contains(enter, "export LEVEL='child'") || !strings.Contains(enter, "export ONLY_CHILD='c'") {
		t.Fatalf("the child's config was not the one applied:\n%s", enter)
	}
	if strings.Contains(enter, "ONLY_PARENT") {
		t.Errorf("the parent's config leaked into the child:\n%s", enter)
	}

	setState(t, stateFromScript(t, enter))
	up := mustBuild(t, parent, false)
	if !strings.Contains(up, "export LEVEL='parent'") || !strings.Contains(up, "export ONLY_PARENT='p'") {
		t.Fatalf("moving up did not switch to the parent's config:\n%s", up)
	}
	if !strings.Contains(up, "unset ONLY_CHILD") {
		t.Errorf("the child's own variable was not restored on the way out:\n%s", up)
	}
}

// bCaseInsensitiveFS answers for the filesystem dir lives on, not for the
// platform: an APFS volume can be either.
func bCaseInsensitiveFS(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "sallyport-case-probe")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(probe) })
	_, err := os.Stat(filepath.Join(dir, "SALLYPORT-CASE-PROBE"))
	return err == nil
}

func bMountTmpfs(t *testing.T, dir string) error {
	t.Helper()
	if err := bMount(dir); err != nil {
		return err
	}
	t.Cleanup(func() {
		if err := bUnmount(dir); err != nil {
			t.Logf("unmounting %s: %v", dir, err)
		}
	})
	return nil
}
