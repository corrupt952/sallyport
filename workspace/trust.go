package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrUntrusted = errors.New("config is not trusted")

// ErrUnsafeTrustStore marks a trust store another user could write to (foreign
// owner or group/world-writable): a grant is just a file whose existence
// authorizes applying a config's env, so any grant it holds may be forged.
var ErrUnsafeTrustStore = errors.New("trust store is not secure")

// ErrUnsafePath marks a config whose path stopped being safe after it was
// approved: a directory above it turned writable, or changed owner.
var ErrUnsafePath = errors.New("config path is not secure")

// Trust records approvals as sha256(config identity + content), so any edit to
// an approved config silently revokes the grant. Without this, cd-ing into a
// cloned repository would apply attacker-controlled env vars (PATH included).

// trustDir reports the one directory grants live in. It refuses to guess rather
// than fall back to a relative base: a cwd-relative store would be invisible
// from the next directory, and any directory the user cd's into could carry its
// own pre-seeded grants. Callers must treat the error as "there is no store",
// not as "the store is empty".
func trustDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base != "" && !filepath.IsAbs(base) {
		base = ""
	}
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot locate the trust store: %w; set HOME, or XDG_DATA_HOME to an absolute path", err)
		}
		// os.UserHomeDir hands back $HOME verbatim on unix, so a relative value
		// arrives without an error and would anchor the store at the cwd.
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("cannot locate the trust store: home directory %q is not an absolute path; set HOME, or XDG_DATA_HOME to an absolute path", home)
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "sallyport", "trust"), nil
}

// ownerUID reports the owning uid of fi. ok is false when Sys() is not the unix
// shape sallyport targets: ownership cannot be proven, so callers must refuse.
func ownerUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// checkOwnerWritable is the strict check, used for the trust store: it demands
// the user's own exclusive ownership, unlike the config side (see trustedOwner).
func checkOwnerWritable(path string, fi os.FileInfo) error {
	uid, ok := ownerUID(fi)
	if !ok {
		return fmt.Errorf("%s: cannot determine owner", path)
	}
	if uid != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not you (uid %d); chown it to yourself", path, uid, os.Getuid())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by others; run: chmod go-w %s", path, path)
	}
	return nil
}

// trustedOwner accepts the current user or root: only root can replace a
// root-owned path, and Nix/home-manager place the config and its symlink target
// in the root-owned store. The trust store does not get this relaxation.
func trustedOwner(uid int) bool {
	return uid == os.Getuid() || uid == 0
}

// checkConfigNode is the rule every node on a config's or a store's path is
// held to: only a trusted owner may change what sallyport is about to read and
// approve. Sticky directories are exempt (see below).
func checkConfigNode(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	uid, ok := ownerUID(fi)
	if !ok {
		return fmt.Errorf("%s: cannot determine owner", path)
	}
	if !trustedOwner(uid) {
		return fmt.Errorf("%s is owned by uid %d (neither you, uid %d, nor root); chown it to yourself", path, uid, os.Getuid())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		// A group/world-writable directory is safe when it is sticky: only an
		// entry's owner may unlink or rename it, so no other user can rename-swap
		// the config inside it (/nix/store is drwxrwxr-t). A writable regular file
		// gets no such pass, being rewritten in place.
		if fi.IsDir() {
			if fi.Mode()&os.ModeSticky != 0 {
				return nil
			}
			return fmt.Errorf("%s is writable by others without the sticky bit; run: chmod go-w %s (a sticky writable dir like /nix/store is allowed, since sticky prevents rename-swap by non-owners)", path, path)
		}
		return fmt.Errorf("%s is writable by others; run: chmod go-w %s", path, path)
	}
	return nil
}

// checkLinkOwner checks only ownership: a symlink's permission bits are ignored
// by the kernel, so what matters is who can repoint it.
func checkLinkOwner(path string, li os.FileInfo) error {
	uid, ok := ownerUID(li)
	if !ok {
		return fmt.Errorf("%s: cannot determine owner", path)
	}
	if !trustedOwner(uid) {
		return fmt.Errorf("%s is a symlink owned by uid %d (neither you, uid %d, nor root); chown it to yourself", path, uid, os.Getuid())
	}
	return nil
}

// verifyTrustStore locates the trust store and rejects one an attacker could
// tamper with. A missing store holds no grants and is not an error (Trust
// creates it with 0o700); a store whose location cannot be determined is
// refused (see trustDir).
func verifyTrustStore() (string, error) {
	dir, err := trustDir()
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return dir, nil
	}
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s exists but is not a directory; remove it", dir)
	}
	// os.Stat followed the link, so the store's own node still has to answer for
	// itself: whoever owns it, or the directory holding it, chooses which store
	// the grants are read from.
	if li, err := os.Lstat(dir); err == nil && li.Mode()&os.ModeSymlink != 0 {
		if err := checkLinkOwner(dir, li); err != nil {
			return "", err
		}
		if err := checkPath(filepath.Dir(dir)); err != nil {
			return "", err
		}
	}
	if err := checkOwnerWritable(dir, fi); err != nil {
		return "", err
	}
	if err := checkPath(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// canonical resolves path aliases (macOS /tmp -> /private/tmp, symlinked
// checkouts) to one identity: a grant or state recorded through one alias
// must match accesses through any other.
func canonical(path string) (string, error) {
	// Made absolute without cleaning: filepath.Abs would cancel "x/.." as text,
	// and that is only the same thing the kernel does when x is a real
	// directory. Through a symlink the kernel goes up from wherever the link
	// landed, so cleaning first names a different node.
	abs := path
	if !filepath.IsAbs(abs) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		abs = wd + string(filepath.Separator) + abs
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	return filepath.Clean(abs), nil
}

// configIdentity is the canonical directory a config lives in joined with its
// file name; the final element is deliberately NOT symlink-resolved. A config
// deployed as a symlink (Nix/home-manager) keeps its identity across a rebuild
// that moves the target, while an edit to the target's bytes still changes the
// fingerprint. The directory IS resolved, so directory aliases map to one
// identity.
func configIdentity(path string) (string, error) {
	// Split before cleaning, for the reason canonical gives: filepath.Dir would
	// cancel a ".." that the kernel resolves from somewhere else.
	name := path
	parent := "."
	if i := strings.LastIndex(path, string(filepath.Separator)); i >= 0 {
		name, parent = path[i+1:], path[:i]
	}
	dir, err := canonical(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func fingerprint(path string) (string, error) {
	id, err := configIdentity(path)
	if err != nil {
		return "", err
	}
	content, err := readConfigFile(id)
	if err != nil {
		return "", err
	}
	return fingerprintBytes(id, content), nil
}

func fingerprintBytes(abs string, content []byte) string {
	h := sha256.New()
	h.Write([]byte(abs))
	h.Write([]byte{0})
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// IsTrusted answers whether a grant exists for the bytes currently on disk.
// Nothing that intends to apply the config may use it: asking here and applying
// afterwards reads the file twice and reopens the very window LoadTrustedConfig
// exists to close. It is for inspecting grant state only.
func IsTrusted(path string) bool {
	_, _, err := LoadTrustedConfig(path)
	return err == nil
}

// LoadTrustedConfig reads the config exactly once, verifies the trust grant
// against those bytes, and parses the very same bytes. Verifying and parsing
// on separate reads would leave a window where the approved content and the
// applied content differ (TOCTOU). The returned fingerprint identifies the
// exact bytes that were applied, so callers can detect an edit even when the
// new content is already trusted again.
func LoadTrustedConfig(path string) (Config, string, error) {
	// A forgeable or unlocatable store invalidates every grant, so refuse before
	// reading the config; wrapped so callers can match ErrUnsafeTrustStore.
	dir, err := verifyTrustStore()
	if err != nil {
		return Config{}, "", fmt.Errorf("%w: %v", ErrUnsafeTrustStore, err)
	}
	id, err := configIdentity(path)
	if err != nil {
		return Config{}, "", err
	}
	if err := checkStoreOutsideWorkspace(dir, id); err != nil {
		return Config{}, "", fmt.Errorf("%w: %v", ErrUnsafeTrustStore, err)
	}
	content, err := readConfigFile(id)
	if err != nil {
		return Config{}, "", err
	}
	fp := fingerprintBytes(id, content)
	// Only a regular file is a grant. A directory or a symlink with the right
	// name would otherwise authorize the config while resisting untrust, which
	// reads records back.
	if gi, err := os.Lstat(filepath.Join(dir, fp)); err != nil || !gi.Mode().IsRegular() {
		return Config{}, "", ErrUntrusted
	}
	// Approval said the path was safe once; the hook runs on every prompt, and
	// what was safe then can be writable now.
	if err := checkConfigTree(id); err != nil {
		return Config{}, "", fmt.Errorf("%w: %v", ErrUnsafePath, err)
	}
	cfg, err := parseConfig(id, content)
	return cfg, fp, err
}

func Trust(path string) error {
	id, err := configIdentity(path)
	if err != nil {
		return err
	}
	// Reject a config someone else could swap between review and approval: the
	// grant would then vouch for bytes the human never saw.
	if err := checkConfigTree(path); err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	content, err := readConfigFile(id)
	if err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	fp := fingerprintBytes(id, content)
	// A grant for unparseable bytes would warn on every cd instead of failing here.
	if _, err := parseConfig(id, content); err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	// An existing store must be secure before a grant joins it; a missing one is
	// created below with 0o700.
	dir, err := verifyTrustStore()
	if err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	if err := checkStoreOutsideWorkspace(dir, id); err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// The record's content is the config identity. Written via rename: lookups
	// test mere existence, so a crash mid-write must not leave a partial record
	// behind that would pass as a valid grant.
	record := filepath.Join(dir, fp)
	// A name of its own per write, so two shells trusting at once cannot rename
	// each other's half-written record away; prune sweeps what a crash leaves.
	tmp, err := os.CreateTemp(dir, fp+".*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.WriteString(id + "\n"); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), record); err != nil {
		return err
	}
	Ok("trusted %s", id)
	return nil
}

// listTrustStore is a variable so tests can reproduce listing failures the
// filesystem cannot be made to produce on demand (a saturated descriptor table,
// EIO, a stale NFS handle), all of which have to be surfaced rather than
// answered with "not trusted".
var listTrustStore = os.ReadDir

// Untrust matches records by their recorded config identity, not by a
// fingerprint of the current content. A grant is keyed by sha256(identity +
// content), so once the config is edited the current fingerprint names no record
// and the stale grant for the original bytes would survive on disk, reviving
// trust the moment the content is restored.
func Untrust(path string) error {
	// Surface an insecure or unlocatable store rather than answering "not
	// trusted": that verdict is how a live grant survives an untrust the user
	// believes went through.
	dir, err := verifyTrustStore()
	if err != nil {
		return fmt.Errorf("refusing to untrust: %w", err)
	}
	target, err := configIdentity(path)
	if err != nil {
		return err
	}
	entries, err := listTrustStore(dir)
	if os.IsNotExist(err) {
		return fmt.Errorf("not trusted: %s", target)
	}
	if err != nil {
		// A permission or I/O error is not proof the grant is absent; a store the
		// user cannot list may still hold a live grant.
		return err
	}
	removed := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		// A directory can never be a grant, and reading it would fail with EISDIR,
		// which the branch below refuses to ignore: one stray directory would then
		// make every untrust impossible.
		if e.IsDir() {
			continue
		}
		record := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(record)
		if os.IsNotExist(err) {
			// A concurrent untrust or prune won the race.
			continue
		}
		if err != nil {
			// A record that cannot be read may be the very grant being revoked;
			// skipping it would leave trust in force while reporting "not trusted".
			return err
		}
		if strings.TrimSpace(string(data)) != target {
			continue
		}
		// A concurrent removal is fine: the goal, no grant on disk, is met.
		if err := os.Remove(record); err != nil && !os.IsNotExist(err) {
			return err
		}
		removed++
	}
	if removed == 0 {
		return fmt.Errorf("not trusted: %s", target)
	}
	Ok("untrusted %s", target)
	return nil
}

// Prune removes grants whose recorded path holds nothing at all, plus leftovers
// of interrupted writes. "Holds nothing" is deliberately weaker than FindRoot's
// "is a regular file": a config symlink whose target is mid-replacement still
// has a file at that path, and a dangling one keeps its grant until untrust
// removes it. Keeping a grant is reversible and applies to nothing on its own
// (the fingerprint still has to match); deleting a live one is neither.
//
// Grants for edited configs are kept on the same reasoning: restoring the
// original bytes legitimately revives them.
func Prune() error {
	dir, err := verifyTrustStore()
	if err != nil {
		return fmt.Errorf("refusing to prune: %w", err)
	}
	entries, err := listTrustStore(dir)
	if os.IsNotExist(err) {
		Info("nothing to prune")
		return nil
	}
	if err != nil {
		return err
	}
	removed := 0
	for _, e := range entries {
		record := filepath.Join(dir, e.Name())
		if strings.HasSuffix(e.Name(), ".tmp") {
			if err := os.Remove(record); err != nil && !os.IsNotExist(err) {
				return err
			}
			removed++
			continue
		}
		data, err := os.ReadFile(record)
		if err != nil {
			continue
		}
		path := strings.TrimSpace(string(data))
		if path == "" {
			if err := os.Remove(record); err != nil && !os.IsNotExist(err) {
				return err
			}
			removed++
			continue
		}
		// Lstat, not Stat: see the presence rule above.
		if _, err := os.Lstat(path); err != nil {
			if !os.IsNotExist(err) {
				// A permission or I/O error is not proof the config is gone;
				// removing the grant on a guess would revoke a valid one.
				Warn("cannot stat %s, keeping grant: %v", path, err)
				continue
			}
			if err := os.Remove(record); err != nil && !os.IsNotExist(err) {
				return err
			}
			removed++
			Ok("removed grant for missing %s", path)
		}
	}
	Info("pruned %d record(s)", removed)
	return nil
}
