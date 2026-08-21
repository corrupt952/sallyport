package workspace

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// pathCheckConfig is the config every layout in these files carries, so a
// verdict can only come from where the file sits and who owns the path to it.
const pathCheckConfig = `{"env": {"FOO": "bar"}}`

// pathCheckBase returns a canonical temporary directory. $TMPDIR is reached
// through /tmp -> /private/tmp on macOS, and the refusals asserted below name
// the path the checks resolved to.
func pathCheckBase(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if c, err := filepath.EvalSymlinks(base); err == nil {
		base = c
	}
	return base
}

// pathCheckHome points HOME at a fresh directory and clears XDG_DATA_HOME, so
// the config walk and the trust store walk both end inside a tree this test
// owns rather than climbing into the host's directories. The real home is never
// touched.
func pathCheckHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(pathCheckBase(t), "home")
	mkdirMode(t, home, 0o755)
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	return home
}

// pathCheckHomeStoreOutside is pathCheckHome with the trust store moved out of
// HOME, so a rule applied to HOME itself can be attributed to the config side
// rather than to the store's own ancestry.
func pathCheckHomeStoreOutside(t *testing.T) string {
	t.Helper()
	base := pathCheckBase(t)
	skipIfHostTreeIsUnsafe(t, base)
	home := filepath.Join(base, "home")
	mkdirMode(t, home, 0o755)
	data := filepath.Join(base, "data")
	mkdirMode(t, data, 0o700)
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", data)
	return home
}

// skipIfHostTreeIsUnsafe skips when a directory above the temporary tree is
// itself owned by someone else or writable by them: every refusal below would
// then be the host's doing rather than the layout's. Only the cases whose walk
// leaves HOME need it.
func skipIfHostTreeIsUnsafe(t *testing.T, dir string) {
	t.Helper()
	for p := dir; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			t.Skipf("cannot stat %s: %v", p, err)
		}
		uid, ok := ownerUID(fi)
		if !ok || !trustedOwner(uid) {
			t.Skipf("%s is owned by uid %d; the host tree cannot carry these layouts", p, uid)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			t.Skipf("%s is writable by others; the host tree cannot carry these layouts", p)
		}
		if filepath.Dir(p) == p {
			return
		}
	}
}

// mkdirMode creates dir and its missing parents, then sets dir's mode
// explicitly: MkdirAll applies the umask, which is exactly what a case asking
// for 0777 or 0775 must not get.
func mkdirMode(t *testing.T, dir string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	chmodMode(t, dir, perm)
}

// chmodMode restores the previous mode at cleanup: a directory left unsearchable
// defeats t.TempDir's own removal.
func chmodMode(t *testing.T, path string, perm os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, fi.Mode().Perm()) })
}

// newWorkspaceAt makes dir a workspace holding the default config.
func newWorkspaceAt(t *testing.T, dir string) string {
	t.Helper()
	mkdirMode(t, dir, 0o755)
	writeConfig(t, dir, pathCheckConfig)
	return ConfigPath(dir)
}

// foreignUID is a uid that is neither the test process nor root, so a node it
// owns is refused whichever of the two the tests run as.
func foreignUID() int {
	if os.Getuid() == 2000 {
		return 2001
	}
	return 2000
}

// chownTo hands path to uid, skipping the case where the process may not chown.
// Ownership layouts cannot be faked: they exist only where the tests run as
// root, which is the container run this suite is also verified under.
func chownTo(t *testing.T, path string, uid int) {
	t.Helper()
	if err := os.Chown(path, uid, -1); err != nil {
		t.Skipf("cannot give %s to uid %d: %v", path, uid, err)
	}
}

// lchownTo is chownTo for the link node itself rather than its target.
func lchownTo(t *testing.T, path string, uid int) {
	t.Helper()
	if err := os.Lchown(path, uid, -1); err != nil {
		t.Skipf("cannot give the link %s to uid %d: %v", path, uid, err)
	}
}

// mentions reports whether err names path, in either the spelling the test
// built or the one the checks resolve it to.
func mentions(err error, path string) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), path) {
		return true
	}
	if c, e := filepath.EvalSymlinks(path); e == nil {
		return strings.Contains(err.Error(), c)
	}
	return false
}

// assertRefusedNaming demands both halves of a refusal: the verdict, and the
// node the user has to fix. An error that does not say which directory is at
// fault leaves them guessing.
func assertRefusedNaming(t *testing.T, err error, node string) {
	t.Helper()
	if err == nil {
		t.Fatalf("layout accepted; want a refusal naming %s", node)
	}
	if !mentions(err, node) {
		t.Errorf("got %v, want a refusal naming %s", err, node)
	}
}

// trustWithin runs Trust off the test goroutine so a check that follows links
// itself cannot wedge the run: a loop or an over-long chain has to end in an
// error, not a hang.
func trustWithin(t *testing.T, path string, d time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- Trust(path) }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("Trust did not return within %s", d)
		return nil
	}
}

// stickyFile sets the sticky bit on a regular file, which does not stop anyone
// from writing to it: the exemption in the rules is for directories only.
func stickyFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, os.ModeSticky|0o666); err != nil {
		t.Skipf("cannot set the sticky bit on a regular file: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSticky == 0 {
		t.Skip("the filesystem drops the sticky bit on regular files")
	}
}

// A-01..A-09: the config file itself and the directory holding it, which is the
// range the checks have always covered.
func TestTrustChecksConfigFileAndItsDirectory(t *testing.T) {
	cases := []struct {
		id, name string
		// arrange mutates the layout and returns the node the refusal must name;
		// an empty node means the layout has to be accepted.
		arrange func(t *testing.T, ws, cfg string) string
		// hint is a substring the refusal must carry, so the user is told what to
		// run rather than only what is wrong.
		hint string
	}{
		{id: "A-01", name: "world-writable config", hint: "chmod", arrange: func(t *testing.T, ws, cfg string) string {
			chmodMode(t, cfg, 0o666)
			return cfg
		}},
		{id: "A-02", name: "group-writable config", arrange: func(t *testing.T, ws, cfg string) string {
			chmodMode(t, cfg, 0o664)
			return cfg
		}},
		{id: "A-03", name: "world-writable directory", hint: "chmod", arrange: func(t *testing.T, ws, cfg string) string {
			chmodMode(t, ws, 0o777)
			return ws
		}},
		{id: "A-04", name: "group-writable directory", arrange: func(t *testing.T, ws, cfg string) string {
			chmodMode(t, ws, 0o775)
			return ws
		}},
		{id: "A-05", name: "sticky world-writable directory", arrange: func(t *testing.T, ws, cfg string) string {
			chmodMode(t, ws, 0o777|os.ModeSticky)
			return ""
		}},
		{id: "A-06", name: "config owned by another user", arrange: func(t *testing.T, ws, cfg string) string {
			chownTo(t, cfg, foreignUID())
			return cfg
		}},
		{id: "A-07", name: "root-owned config and directory", arrange: func(t *testing.T, ws, cfg string) string {
			chownTo(t, cfg, 0)
			chownTo(t, ws, 0)
			return ""
		}},
		{id: "A-08", name: "world-writable root-owned config", arrange: func(t *testing.T, ws, cfg string) string {
			chownTo(t, cfg, 0)
			chmodMode(t, cfg, 0o666)
			return cfg
		}},
		{id: "A-09", name: "sticky config file", arrange: func(t *testing.T, ws, cfg string) string {
			stickyFile(t, cfg)
			return cfg
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			home := pathCheckHome(t)
			ws := filepath.Join(home, "ws")
			cfg := newWorkspaceAt(t, ws)

			node := tc.arrange(t, ws, cfg)
			err := Trust(cfg)
			if node == "" {
				if err != nil {
					t.Fatalf("refused a safe layout: %v", err)
				}
				if !IsTrusted(cfg) {
					t.Error("config not trusted after Trust")
				}
				return
			}
			assertRefusedNaming(t, err, node)
			if tc.hint != "" && !strings.Contains(err.Error(), tc.hint) {
				t.Errorf("got %v, want a refusal telling the user to run %s", err, tc.hint)
			}
			if IsTrusted(cfg) {
				t.Error("a refused config is reported trusted")
			}
		})
	}
}

// A-06: the refusal has to carry both uids, or a user whose file was created by
// a deployment tool cannot tell whose it became.
func TestTrustNamesBothUidsForAForeignConfig(t *testing.T) {
	home := pathCheckHome(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	chownTo(t, cfg, foreignUID())

	err := Trust(cfg)
	if err == nil {
		t.Fatal("Trust accepted a config owned by another user")
	}
	for _, want := range []string{fmt.Sprint(foreignUID()), fmt.Sprint(os.Getuid())} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("got %v, want a refusal naming uid %s", err, want)
		}
	}
}

// A-10: create writes the template first and approves it second, so a directory
// nothing can be approved in leaves a file behind. The failure has to say the
// approval is what did not happen, or the next prompt's warning comes as a
// surprise.
func TestCreateInUnsafeDirectoryReportsTheUnapprovedFile(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	mkdirMode(t, ws, 0o777)

	err := Create(ws)
	if err == nil {
		t.Fatal("Create approved a template in a world-writable directory")
	}
	if !strings.Contains(err.Error(), "trust") {
		t.Errorf("got %v, want a failure attributed to the approval", err)
	}
	if _, statErr := os.Stat(ConfigPath(ws)); statErr != nil {
		t.Errorf("template not on disk after a failed Create: %v", statErr)
	}
	if IsTrusted(ConfigPath(ws)) {
		t.Error("the template Create could not approve is reported trusted")
	}
}

// ancestorChain builds home/d1/d2/... depth levels deep with the config in the
// innermost one, and returns the levels outermost first.
func ancestorChain(t *testing.T, home string, depth int) ([]string, string) {
	t.Helper()
	levels := make([]string, 0, depth)
	dir := home
	for i := 1; i <= depth; i++ {
		dir = filepath.Join(dir, fmt.Sprintf("d%d", i))
		mkdirMode(t, dir, 0o755)
		levels = append(levels, dir)
	}
	writeConfig(t, dir, pathCheckConfig)
	return levels, ConfigPath(dir)
}

// A-11: a writable grandparent is enough. The subtree holding the config can be
// renamed away wholesale and an attacker's put in its place, and since the grant
// is keyed on the path and the content, a byte-identical copy still applies.
func TestTrustRefusesAWritableGrandparent(t *testing.T) {
	home := pathCheckHome(t)
	levels, cfg := ancestorChain(t, home, 2)
	chmodMode(t, levels[0], 0o777)

	assertRefusedNaming(t, Trust(cfg), levels[0])
}

// A-12: one directory anywhere in the chain is enough, at any depth. A check
// that only looks at the first ancestor passes at depth 1 and fails here.
func TestTrustRefusesAWritableAncestorAtEveryDepth(t *testing.T) {
	for _, depth := range []int{2, 3, 5, 10} {
		for level := 0; level < depth; level++ {
			t.Run(fmt.Sprintf("depth%d/level%d", depth, level+1), func(t *testing.T) {
				home := pathCheckHome(t)
				levels, cfg := ancestorChain(t, home, depth)
				chmodMode(t, levels[level], 0o777)

				assertRefusedNaming(t, Trust(cfg), levels[level])
			})
		}
	}
}

// A-13..A-17: what an ancestor's owner and mode mean. Two levels above the
// config, so a check that stops at the parent cannot pass by accident.
func TestTrustJudgesAnAncestorsOwnerAndMode(t *testing.T) {
	cases := []struct {
		id, name   string
		arrange    func(t *testing.T, dir string)
		accept     bool
		skipAsRoot bool
	}{
		{id: "A-13", name: "owned by another user", arrange: func(t *testing.T, dir string) {
			chownTo(t, dir, foreignUID())
		}},
		{id: "A-14", name: "sticky world-writable", accept: true, arrange: func(t *testing.T, dir string) {
			chmodMode(t, dir, 0o777|os.ModeSticky)
		}},
		{id: "A-15", name: "root-owned drwxrwxr-t", accept: true, arrange: func(t *testing.T, dir string) {
			chmodMode(t, dir, 0o775|os.ModeSticky)
			chownTo(t, dir, 0)
		}},
		{id: "A-16", name: "search-only", accept: true, arrange: func(t *testing.T, dir string) {
			chmodMode(t, dir, 0o111)
		}},
		{id: "A-17", name: "unreadable and unsearchable", skipAsRoot: true, arrange: func(t *testing.T, dir string) {
			chmodMode(t, dir, 0o000)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			if tc.skipAsRoot {
				skipIfRoot(t)
			}
			home := pathCheckHome(t)
			levels, cfg := ancestorChain(t, home, 3)
			tc.arrange(t, levels[0])

			err := Trust(cfg)
			if tc.accept {
				if err != nil {
					t.Fatalf("refused a safe ancestor: %v", err)
				}
				return
			}
			assertRefusedNaming(t, err, levels[0])
		})
	}
}

// A-18: HOME is where the walk stops, and it is checked before it stops. A walk
// that gives up one directory early accepts everything below a home anyone can
// write to. The store is outside HOME here so only the config side can account
// for the refusal.
func TestTrustRefusesAWorldWritableHome(t *testing.T) {
	home := pathCheckHomeStoreOutside(t)
	cfg := newWorkspaceAt(t, filepath.Join(home, "ws"))
	chmodMode(t, home, 0o777)

	assertRefusedNaming(t, Trust(cfg), home)
}

// A-19: approval is not a permanent verdict. The hook runs on every prompt, so a
// directory that turned world-writable after the approval has to stop the apply
// rather than keep it running until the next cd.
func TestExportRefusesWhenAnAncestorTurnedWritable(t *testing.T) {
	home := pathCheckHome(t)
	levels, cfg := ancestorChain(t, home, 2)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	// Entered first, so the refusal has something to take back: this is the case
	// that matters, a workspace already applied when its path stops being safe.
	entered, err := BuildExportScript(filepath.Dir(cfg), false)
	if err != nil {
		t.Fatal(err)
	}
	setState(t, stateFromScript(t, entered.Script))
	chmodMode(t, levels[0], 0o777)

	res, err := BuildExportScript(filepath.Dir(cfg), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Script, "FOO=") {
		t.Errorf("applied a config under a world-writable ancestor:\n%s", res.Script)
	}
	if !hasWarning(res.Warnings, filepath.Dir(cfg)) && !hasWarning(res.Warnings, levels[0]) {
		t.Errorf("got warnings %q, want one naming the workspace or %s", res.Warnings, levels[0])
	}
	// A path that stopped being safe has to leave the shell as if there were no
	// workspace here at all. Recorded as entered instead, the shell believes it
	// is inside a workspace sallyport just refused to apply, and leaving never
	// restores anything because there is nothing recorded as applied.
	if !strings.Contains(res.Script, stateShellVar+"=''") {
		t.Errorf("state root = %q, want the state cleared: a refused workspace must not be recorded as entered",
			stateFromScript(t, res.Script).Root)
	}
	// "broken" would send the user to the config file, which is fine; what
	// changed is the directory above it.
	for _, w := range res.Warnings {
		if strings.Contains(w, "ignoring broken") {
			t.Errorf("warning blames the config file: %q", w)
		}
	}
}

// A-20: the grant is sha256(identity + content), so a tree swapped for another
// user's with a byte-identical config still matches it. What has to stop the
// apply is who owns the tree that is there now, since WORKSPACE_PATH and every
// PATH-shaped value in it would point into theirs.
func TestExportRefusesAfterTheWorkspaceTreeIsSwapped(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}

	theirs := filepath.Join(home, "theirs")
	mkdirMode(t, theirs, 0o755)
	writeConfig(t, theirs, pathCheckConfig)
	chownTo(t, ConfigPath(theirs), foreignUID())
	chownTo(t, theirs, foreignUID())
	if err := os.RemoveAll(ws); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(theirs, ws); err != nil {
		t.Fatal(err)
	}

	res, err := BuildExportScript(ws, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Script, "FOO=") {
		t.Errorf("applied a config out of another user's tree:\n%s", res.Script)
	}
}

// A-22: the verdict for a directory must not depend on how far above the config
// it sits. The outermost level is mutated at every depth, so "only the first
// ancestor" and "every ancestor but the last" both fail here.
func TestAncestorVerdictIsIndependentOfDepth(t *testing.T) {
	kinds := []struct {
		name    string
		arrange func(t *testing.T, dir string)
		accept  bool
	}{
		{name: "self 0755", accept: true, arrange: func(t *testing.T, dir string) {}},
		{name: "self 0775", arrange: func(t *testing.T, dir string) { chmodMode(t, dir, 0o775) }},
		{name: "self 0777 sticky", accept: true, arrange: func(t *testing.T, dir string) {
			chmodMode(t, dir, 0o777|os.ModeSticky)
		}},
		{name: "root 0755", accept: true, arrange: func(t *testing.T, dir string) { chownTo(t, dir, 0) }},
		{name: "root 0777 sticky", accept: true, arrange: func(t *testing.T, dir string) {
			chmodMode(t, dir, 0o777|os.ModeSticky)
			chownTo(t, dir, 0)
		}},
		{name: "other 0755", arrange: func(t *testing.T, dir string) { chownTo(t, dir, foreignUID()) }},
		{name: "other 0777", arrange: func(t *testing.T, dir string) {
			chmodMode(t, dir, 0o777)
			chownTo(t, dir, foreignUID())
		}},
	}
	for _, k := range kinds {
		for depth := 1; depth <= 5; depth++ {
			t.Run(fmt.Sprintf("%s/depth%d", k.name, depth), func(t *testing.T) {
				home := pathCheckHome(t)
				levels, cfg := ancestorChain(t, home, depth)
				k.arrange(t, levels[0])

				err := Trust(cfg)
				if k.accept {
					if err != nil {
						t.Fatalf("refused at depth %d what is accepted elsewhere: %v", depth, err)
					}
					return
				}
				assertRefusedNaming(t, err, levels[0])
			})
		}
	}
}

// A-23: the Nix and home-manager shape. The identity is the link's own location,
// so a rebuild that moves the target keeps the approval.
func TestTrustSymlinkedConfigKeepsItsLinkLocationIdentity(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := symlinkConfig(t, ws, filepath.Join(home, "store", "config"), pathCheckConfig)

	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(cfg) {
		t.Fatal("symlinked config not trusted after Trust")
	}
	id, err := configIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if id != ConfigPath(ws) {
		t.Errorf("identity = %q, want the link's own location %q", id, ConfigPath(ws))
	}
}

// A-24..A-27: a symlinked config has two nodes to answer for, and both of them
// have ancestors. Lstat and Stat answer different questions here, and using one
// where the other belongs removes a whole check silently.
func TestTrustChecksBothTheLinkAndItsTarget(t *testing.T) {
	cases := []struct {
		id, name string
		// arrange returns the node the refusal must name. link is the config
		// symlink and target the file it resolves to.
		arrange func(t *testing.T, link, target string) string
	}{
		{id: "A-24", name: "link owned by another user", arrange: func(t *testing.T, link, target string) string {
			lchownTo(t, link, foreignUID())
			return link
		}},
		{id: "A-25", name: "target owned by another user", arrange: func(t *testing.T, link, target string) string {
			chownTo(t, target, foreignUID())
			return target
		}},
		{id: "A-26", name: "target directory writable", arrange: func(t *testing.T, link, target string) string {
			chmodMode(t, filepath.Dir(target), 0o777)
			return filepath.Dir(target)
		}},
		{id: "A-27", name: "target grandparent writable", arrange: func(t *testing.T, link, target string) string {
			up := filepath.Dir(filepath.Dir(target))
			chmodMode(t, up, 0o777)
			return up
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			home := pathCheckHome(t)
			target := filepath.Join(home, "deploy", "gen", "config")
			link := symlinkConfig(t, filepath.Join(home, "ws"), target, pathCheckConfig)

			node := tc.arrange(t, link, target)
			assertRefusedNaming(t, Trust(link), node)
			if IsTrusted(link) {
				t.Error("a refused config is reported trusted")
			}
		})
	}
}

// A-28: a relative target resolves against the directory the link sits in, not
// against the working directory. Statting it as given picks up a different node
// entirely, one the user never deployed.
func TestTrustResolvesARelativeSymlinkTargetAgainstTheLink(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	mkdirMode(t, ws, 0o755)
	real := filepath.Join(home, "real")
	mkdirMode(t, real, 0o755)
	if err := os.WriteFile(filepath.Join(real, "x.jsonc"), []byte(pathCheckConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	chmodMode(t, filepath.Join(real, "x.jsonc"), 0o666)
	// The decoy sits where "../real/x.jsonc" lands when it is resolved against
	// the working directory instead, and is perfectly safe.
	decoy := filepath.Join(home, "work", "real")
	mkdirMode(t, decoy, 0o755)
	if err := os.WriteFile(filepath.Join(decoy, "x.jsonc"), []byte(pathCheckConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	here := filepath.Join(home, "work", "here")
	mkdirMode(t, here, 0o755)
	t.Chdir(here)

	cfg := ConfigPath(ws)
	if err := os.Symlink(filepath.Join("..", "real", "x.jsonc"), cfg); err != nil {
		t.Fatal(err)
	}
	assertRefusedNaming(t, Trust(cfg), filepath.Join(real, "x.jsonc"))
}

// A-29: a ".." right after a symlink cannot be cancelled on the page. The kernel
// walks it from the link's target, so a lexical cleanup checks one file and
// reads another.
func TestTrustFollowsDotDotThroughASymlinkTheWayTheKernelDoes(t *testing.T) {
	home := pathCheckHome(t)
	// a/b is a symlink to c/d, so a/b/../e is c/e and not a/e.
	realDir := filepath.Join(home, "c", "d")
	mkdirMode(t, realDir, 0o755)
	unsafeDir := filepath.Join(home, "c", "e")
	mkdirMode(t, unsafeDir, 0o777)
	if err := os.WriteFile(filepath.Join(unsafeDir, "x.jsonc"), []byte(pathCheckConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	lexicalDir := filepath.Join(home, "a", "e")
	mkdirMode(t, lexicalDir, 0o755)
	if err := os.WriteFile(filepath.Join(lexicalDir, "x.jsonc"), []byte(pathCheckConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	mkdirMode(t, filepath.Join(home, "a"), 0o755)
	if err := os.Symlink(realDir, filepath.Join(home, "a", "b")); err != nil {
		t.Fatal(err)
	}

	// Concatenated rather than composed with filepath.Join, which would cancel
	// the ".." before anything under test sees it.
	cfg := home + "/a/b/../e/x.jsonc"
	assertRefusedNaming(t, Trust(cfg), unsafeDir)
}

// symlinkChain points cfg at target through hops intermediate links, the way
// home-manager reaches a generation through its gcroots. The returned slice is
// every link node, starting at cfg.
func symlinkChain(t *testing.T, dir, cfg, target string, hops int) []string {
	t.Helper()
	mkdirMode(t, dir, 0o755)
	links := []string{}
	prev := target
	for i := hops; i >= 1; i-- {
		l := filepath.Join(dir, fmt.Sprintf("hop%d", i))
		if err := os.Symlink(prev, l); err != nil {
			t.Fatal(err)
		}
		links = append([]string{l}, links...)
		prev = l
	}
	if err := os.Symlink(prev, cfg); err != nil {
		t.Fatal(err)
	}
	return append([]string{cfg}, links...)
}

// chainLayout builds a workspace whose config is reached through links links in
// total, all owned by the test user.
func chainLayout(t *testing.T, home string, links int) (string, []string) {
	t.Helper()
	target := filepath.Join(home, "store", "config")
	mkdirMode(t, filepath.Dir(target), 0o755)
	if err := os.WriteFile(target, []byte(pathCheckConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(home, "ws")
	mkdirMode(t, ws, 0o755)
	return target, symlinkChain(t, filepath.Join(home, "hops"), ConfigPath(ws), target, links-1)
}

// A-30: home-manager reaches its generation through five to eight links. A hop
// budget picked to bound the walk rejects that deployment outright.
func TestTrustAcceptsMultiHopSymlinkChains(t *testing.T) {
	for _, links := range []int{2, 3, 8} {
		t.Run(fmt.Sprintf("%dlinks", links), func(t *testing.T) {
			home := pathCheckHome(t)
			_, nodes := chainLayout(t, home, links)

			if err := Trust(nodes[0]); err != nil {
				t.Fatalf("refused a %d-link chain: %v", links, err)
			}
			if !IsTrusted(nodes[0]) {
				t.Error("config reached through the chain is not trusted")
			}
		})
	}
}

// A-31: only the first link and the final target are obvious. A link in the
// middle can be repointed by whoever owns it, which decides what the last one
// resolves to.
func TestTrustChecksTheOwnerOfEveryHopInAChain(t *testing.T) {
	home := pathCheckHome(t)
	_, nodes := chainLayout(t, home, 3)
	middle := nodes[1]
	lchownTo(t, middle, foreignUID())

	assertRefusedNaming(t, Trust(nodes[0]), middle)
}

// A-32: the directory a middle hop sits in decides whether that hop can be
// swapped for another, which is the same exposure as owning the link.
func TestTrustChecksTheDirectoryOfEveryHopInAChain(t *testing.T) {
	home := pathCheckHome(t)
	_, nodes := chainLayout(t, home, 3)
	mid := filepath.Dir(nodes[1])
	chmodMode(t, mid, 0o777)

	assertRefusedNaming(t, Trust(nodes[0]), mid)
}

// A-33: a loop has to end in an error. A walk written by hand recurses through
// it until the stack is gone, and the hook that calls it runs on every prompt.
func TestTrustRefusesASymlinkLoop(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	mkdirMode(t, ws, 0o755)
	cfg := ConfigPath(ws)
	other := filepath.Join(ws, "other")
	if err := os.Symlink(other, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cfg, other); err != nil {
		t.Fatal(err)
	}

	err := trustWithin(t, cfg, 10*time.Second)
	if err == nil {
		t.Fatal("Trust accepted a symlink loop")
	}
	if !mentions(err, cfg) {
		t.Errorf("got %v, want an error naming %s", err, cfg)
	}
}

// A-34: past the kernel's own limit the walk ends in ELOOP rather than running
// on. The accepted length is pinned by TestTrustAcceptsMultiHopSymlinkChains, so
// this cannot be satisfied by lowering the budget.
func TestTrustRefusesAnOverlongSymlinkChain(t *testing.T) {
	home := pathCheckHome(t)
	_, nodes := chainLayout(t, home, 60)

	if err := trustWithin(t, nodes[0], 10*time.Second); err == nil {
		t.Fatal("Trust accepted a 60-link chain")
	}
}

// A-35: a directory component of the path can be a symlink too, and Stat follows
// it without anyone having looked at who owns it. Repointed just before the
// approval, it puts the grant on bytes the human never read.
func TestTrustChecksASymlinkedDirectoryComponent(t *testing.T) {
	home := pathCheckHome(t)
	real := filepath.Join(home, "real")
	mkdirMode(t, filepath.Join(real, "proj"), 0o755)
	writeConfig(t, filepath.Join(real, "proj"), pathCheckConfig)
	link := filepath.Join(home, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	lchownTo(t, link, foreignUID())

	cfg := filepath.Join(link, "proj", ConfigFileName)
	assertRefusedNaming(t, Trust(cfg), link)
}

// A-36: /tmp is a symlink to /private/tmp on macOS, so the same workspace is
// reached under two spellings. One approval has to cover both, or every cd
// through the other one asks for it again.
func TestTrustThroughAPrefixSymlinkCoversBothSpellings(t *testing.T) {
	home := pathCheckHome(t)
	real := filepath.Join(home, "real")
	ws := filepath.Join(real, "proj")
	cfg := newWorkspaceAt(t, ws)
	alias := filepath.Join(home, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}

	aliased := filepath.Join(alias, "proj", ConfigFileName)
	if err := Trust(aliased); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(cfg) {
		t.Error("the grant taken through the alias does not cover the real path")
	}
	if !IsTrusted(aliased) {
		t.Error("the grant taken through the alias does not cover the alias")
	}
}

// A-37, A-38: what a grant is keyed on, from both sides. A rebuild moves the
// target and keeps the approval; an edit to the bytes ends it.
func TestSymlinkedGrantTracksContentNotTargetPath(t *testing.T) {
	home := pathCheckHome(t)
	first := filepath.Join(home, "store-1", "config")
	cfg := symlinkConfig(t, filepath.Join(home, "ws"), first, pathCheckConfig)
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}

	second := filepath.Join(home, "store-2", "config")
	mkdirMode(t, filepath.Dir(second), 0o755)
	if err := os.WriteFile(second, []byte(pathCheckConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, cfg); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(cfg) {
		t.Error("A-37: the approval was lost when the store path moved under identical content")
	}

	if err := os.WriteFile(second, []byte(`{"env": {"FOO": "barr"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if IsTrusted(cfg) {
		t.Error("A-38: the approval survived an edit to the target's bytes")
	}
}

// A-39: only a regular file marks a workspace. A link to anything else must not
// stop the search: opening a FIFO blocks the prompt, and a device reads forever.
func TestFindRootIgnoresNonRegularConfigTargets(t *testing.T) {
	cases := []struct {
		id, name string
		// plant creates the config entry inside dir; a skip means the kind cannot
		// be built here.
		plant func(t *testing.T, dir string)
	}{
		{id: "A-39", name: "link to a directory", plant: func(t *testing.T, dir string) {
			target := filepath.Join(dir, "adir")
			mkdirMode(t, target, 0o755)
			if err := os.Symlink(target, ConfigPath(dir)); err != nil {
				t.Fatal(err)
			}
		}},
		{id: "A-39", name: "link to a fifo", plant: func(t *testing.T, dir string) {
			target := filepath.Join(dir, "afifo")
			if err := syscall.Mkfifo(target, 0o644); err != nil {
				t.Skipf("cannot create a fifo: %v", err)
			}
			if err := os.Symlink(target, ConfigPath(dir)); err != nil {
				t.Fatal(err)
			}
		}},
		{id: "A-39", name: "link to a socket", plant: func(t *testing.T, dir string) {
			target := filepath.Join(dir, "asock")
			l, err := net.Listen("unix", target)
			if err != nil {
				t.Skipf("cannot create a unix socket: %v", err)
			}
			t.Cleanup(func() { _ = l.Close() })
			if err := os.Symlink(target, ConfigPath(dir)); err != nil {
				t.Fatal(err)
			}
		}},
		{id: "A-39", name: "link to a character device", plant: func(t *testing.T, dir string) {
			if _, err := os.Stat(os.DevNull); err != nil {
				t.Skipf("no %s: %v", os.DevNull, err)
			}
			if err := os.Symlink(os.DevNull, ConfigPath(dir)); err != nil {
				t.Fatal(err)
			}
		}},
		{id: "A-39", name: "dangling link", plant: func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(dir, "gone"), ConfigPath(dir)); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			home := pathCheckHome(t)
			outer := filepath.Join(home, "outer")
			mkdirMode(t, outer, 0o755)
			writeConfig(t, outer, pathCheckConfig)
			inner := filepath.Join(outer, "inner")
			mkdirMode(t, inner, 0o755)

			tc.plant(t, inner)
			if got := FindRoot(inner); got != outer {
				t.Errorf("FindRoot = %q, want the workspace above it, %q", got, outer)
			}
		})
	}
}

// A-40: a hard link shares the inode, so ownership and mode look the same from
// either name and there is nothing for the path checks to see. The fingerprint
// is the whole defense: content changed through the other name ends the grant.
func TestHardLinkedConfigExpiresOnEditThroughTheOtherName(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	shared := filepath.Join(home, "shared")
	mkdirMode(t, shared, 0o777|os.ModeSticky)
	other := filepath.Join(shared, "copy")
	if err := os.Link(cfg, other); err != nil {
		t.Skipf("cannot hard link: %v", err)
	}
	if err := Trust(cfg); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(other, []byte(`{"env": {"FOO": "theirs"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if IsTrusted(cfg) {
		t.Error("the approval survived an edit made through the other hard link")
	}
}

// A-41: the node that is checked and the node that is read have to be the same
// one. filepath.Abs cancels ".." on the page while the read resolves it through
// the kernel, and a symlink just before it makes those two different files.
func TestTrustChecksTheSameNodeItReads(t *testing.T) {
	home := pathCheckHome(t)
	realParent := filepath.Join(home, "deep")
	unsafe := filepath.Join(realParent, "proj")
	mkdirMode(t, unsafe, 0o755)
	if err := os.WriteFile(ConfigPath(unsafe), []byte(pathCheckConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	chmodMode(t, ConfigPath(unsafe), 0o666)
	// Where the lexical reading of "b/.." lands: a safe file the user would be
	// happy to approve.
	decoy := filepath.Join(home, "proj")
	mkdirMode(t, decoy, 0o755)
	writeConfig(t, decoy, pathCheckConfig)
	if err := os.Symlink(filepath.Join(realParent, "real"), filepath.Join(home, "b")); err != nil {
		t.Fatal(err)
	}
	mkdirMode(t, filepath.Join(realParent, "real"), 0o755)

	// Concatenated rather than composed with filepath.Join, which would cancel
	// the ".." before anything under test sees it.
	cfg := home + "/b/../proj/" + ConfigFileName
	assertRefusedNaming(t, Trust(cfg), ConfigPath(unsafe))
	if IsTrusted(cfg) {
		t.Error("the world-writable config the path really names is reported trusted")
	}
}

// A-42: one workspace, one identity. A grant that depends on how the user
// happened to type the path makes trust come and go with the spelling.
func TestConfigIdentityIsTheSameForEverySpelling(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	mkdirMode(t, filepath.Join(ws, "x"), 0o755)

	want, err := configIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Written out rather than composed with filepath.Join, which cleans them all
	// back into the one spelling this is about telling apart.
	spellings := map[string]string{
		"dot":            ws + "/./" + ConfigFileName,
		"double slash":   ws + "//" + ConfigFileName,
		"dot dot":        ws + "/x/../" + ConfigFileName,
		"trailing slash": ws + "/" + ConfigFileName,
	}
	for name, spelling := range spellings {
		t.Run(name, func(t *testing.T) {
			got, err := configIdentity(spelling)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("identity = %q, want %q", got, want)
			}
		})
	}
}

// A-43: ".." through real directories is ordinary, and refusing it outright
// would reject a path the user typed from a sibling directory.
func TestTrustAcceptsDotDotThroughRealDirectories(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	cfg := newWorkspaceAt(t, ws)
	mkdirMode(t, filepath.Join(home, "sibling"), 0o755)

	viaDotDot := home + "/sibling/../ws/" + ConfigFileName
	if err := Trust(viaDotDot); err != nil {
		t.Fatalf("refused a config named through a real \"..\": %v", err)
	}
	if !IsTrusted(cfg) {
		t.Error("the grant taken through \"..\" does not cover the plain path")
	}
}

// A-44: a trailing or doubled separator is the same directory. FindRoot cleans
// its argument, and this is what says so.
func TestFindRootIgnoresRedundantSeparators(t *testing.T) {
	home := pathCheckHome(t)
	ws := filepath.Join(home, "ws")
	newWorkspaceAt(t, ws)
	mkdirMode(t, filepath.Join(ws, "sub"), 0o755)

	for _, spelling := range []string{ws + "/", ws + "//sub", ws + "/sub/"} {
		t.Run(spelling, func(t *testing.T) {
			if got := FindRoot(spelling); got != ws {
				t.Errorf("FindRoot(%q) = %q, want %q", spelling, got, ws)
			}
		})
	}
}
