package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// pathCheckOptOut disables the ancestor walk. Every tool that checks paths this
// way offers one -- sudo's `Defaults !sudoedit_checkdir`, OpenSSH's
// `StrictModes no`, git's safe.directory -- because the rules refuse layouts
// their owners consider fine: a group-writable home, a shared project tree, a
// filesystem whose mode bits mean nothing.
const pathCheckOptOut = "SALLYPORT_NO_PATH_CHECK"

func pathChecksDisabled() bool { return os.Getenv(pathCheckOptOut) == "1" }

// checkPath verifies every directory the config or the trust store actually
// sits under. Resolution is left to the kernel and the result is walked from
// the root down, so ".." and symlinks never have to be interpreted here: a
// component of a resolved path is always a real directory, which is what makes
// this short. This is the shape of OpenSSH's safe_path.
//
// The walk stops at the home directory when the path is inside it. Whoever can
// write above the home replaces the shell rc that installs sallyport, so
// refusing on those directories protects nothing while rejecting the
// group-writable homes that several distributions create by default.
func checkPath(path string) error {
	if pathChecksDisabled() {
		return nil
	}
	resolved, err := canonical(path)
	if err != nil {
		return err
	}
	stop := homeBoundary()
	for _, dir := range ancestors(resolved, stop) {
		if err := checkConfigNode(dir); err != nil {
			return err
		}
	}
	return nil
}

func ancestors(dir, stop string) []string {
	var chain []string
	for {
		chain = append(chain, dir)
		if dir == stop {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// homeBoundary answers "" when the home cannot be located, which runs the walk
// to the root: a boundary that cannot be established is not one to assume.
func homeBoundary() string {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return ""
	}
	resolved, err := canonical(home)
	if err != nil {
		return ""
	}
	return resolved
}

// maxConfigHops bounds a symlink chain the way the kernel does. Deployments
// that reach a config through home-manager's generation links use five to eight.
const maxConfigHops = 40

// checkConfigTree verifies a config and everything that decides which bytes it
// stands for: every link in the chain, the directory each link sits in, the
// regular file the chain ends at, and the directories above that.
//
// Each hop is followed by hand rather than resolved in one call, because a link
// in the middle of the chain appears in neither the path as written nor the
// path fully resolved, and whoever owns it chooses what the last hop finds.
func checkConfigTree(path string) error {
	if pathChecksDisabled() {
		return nil
	}
	// The directory is resolved before the name is put back on, so that a ".."
	// in the path is applied by the kernel from wherever the components really
	// are. Cancelling it as text checks one file and reads another.
	node, err := configIdentity(path)
	if err != nil {
		return err
	}
	for hops := 0; ; hops++ {
		if hops > maxConfigHops {
			return fmt.Errorf("%s: too many symbolic links", path)
		}
		li, err := os.Lstat(node)
		if err != nil {
			return err
		}
		if li.Mode()&os.ModeSymlink == 0 {
			if err := checkConfigNode(node); err != nil {
				return err
			}
			return checkPath(filepath.Dir(node))
		}
		if err := checkLinkOwner(node, li); err != nil {
			return err
		}
		if err := checkPath(filepath.Dir(node)); err != nil {
			return err
		}
		target, err := os.Readlink(node)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(target) {
			// Resolve the link's own directory before appending the target: the
			// kernel applies a leading ".." to wherever that directory really is,
			// which is not where cancelling it as text would land.
			dir, err := canonical(filepath.Dir(node))
			if err != nil {
				return err
			}
			target = filepath.Join(dir, target)
		}
		node = target
	}
}

// checkStoreOutsideWorkspace refuses a store kept inside the workspace it
// authorizes: a grant committed to the repository would approve that
// repository's config on every machine that checks it out, with nobody
// approving anything.
func checkStoreOutsideWorkspace(storeDir, configPath string) error {
	if pathChecksDisabled() {
		return nil
	}
	store, err := canonical(storeDir)
	if err != nil {
		return err
	}
	ws, err := canonical(filepath.Dir(configPath))
	if err != nil {
		return err
	}
	// The home is not a repository anyone clones, and the default store lives
	// inside it: a config at ~/.sallyport.jsonc is home-manager's own layout.
	if ws == homeBoundary() {
		return nil
	}
	if store == ws || strings.HasPrefix(store, ws+string(filepath.Separator)) {
		return fmt.Errorf("the trust store %s is inside the workspace %s; a grant kept there travels with the repository. Point XDG_DATA_HOME outside it", store, ws)
	}
	return nil
}
