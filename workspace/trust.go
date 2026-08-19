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

// ErrUntrusted marks a config that exists but has no valid trust grant.
var ErrUntrusted = errors.New("config is not trusted")

// ErrUnsafeTrustStore marks a trust store that exists but could be tampered
// with by another user (foreign owner or group/world-writable). A grant is
// just a file whose existence authorizes applying a config's env (PATH
// included), so if someone else can write to the store they can forge one;
// no grant it holds can be trusted. This is what direnv #445 warns about.
var ErrUnsafeTrustStore = errors.New("trust store is not secure")

// Trust records approvals as sha256(config identity + content), so any edit to
// an approved config silently revokes the grant. Without this, cd-ing into a
// cloned repository would apply attacker-controlled env vars (PATH included).

// trustDir reports the one directory grants live in. It refuses to guess: a
// store path that is not anchored at an absolute base would be resolved against
// the working directory, and a per-directory store destroys the whole point of
// the grant. Grants written in one directory would be invisible from the next
// (untrust would answer "not trusted" while the grant is still on disk), and,
// worse, any directory the user can cd into could carry its own pre-seeded
// store: a cloned repository shipping .local/share/sallyport/trust/<hash>
// alongside its config would be applied on arrival, which is exactly the
// approval step sallyport exists to impose. Callers must treat the error as
// "there is no store", not as "the store is empty".
func trustDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	// The XDG base directory spec requires a relative XDG_DATA_HOME to be
	// ignored as invalid, and here that rule is load-bearing rather than
	// pedantic: honouring one is precisely the cwd-relative store above.
	if base != "" && !filepath.IsAbs(base) {
		base = ""
	}
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot locate the trust store: %w; set HOME, or XDG_DATA_HOME to an absolute path", err)
		}
		// os.UserHomeDir reports $HOME verbatim on unix, so a relative value
		// arrives here without an error and would anchor the store at the
		// working directory just as a relative XDG_DATA_HOME would.
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("cannot locate the trust store: home directory %q is not an absolute path; set HOME, or XDG_DATA_HOME to an absolute path", home)
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "sallyport", "trust"), nil
}

// ownerUID reports the owning uid of fi; the bool is false when the platform's
// Sys() is not the unix shape sallyport targets, in which case ownership cannot
// be proven and callers must refuse.
func ownerUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// checkOwnerWritable rejects a path not owned by the current user or writable by
// group or other. This is the strict form: it demands the user's own exclusive
// ownership, used for the trust store, whose files (grants) sallyport itself
// creates and no system component ever should.
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

// trustedOwner reports whether a config-side path owned by uid is acceptable:
// the current user, or root. Root is implicitly trusted because only root can
// replace a root-owned path, and system config managers (Nix/home-manager place
// the config and its symlink target in the root-owned store) depend on this.
// The trust store itself does not use this relaxation — see checkOwnerWritable.
func trustedOwner(uid int) bool {
	return uid == os.Getuid() || uid == 0
}

// checkConfigNode verifies a regular config file, a resolved symlink target, or
// either of their parent directories: it must be owned by the user or root and
// not writable by group or other, so only a trusted owner can change what
// sallyport is about to read and approve. A directory is exempt from the
// writable check when it is sticky (see below), which is what lets root-owned
// configs under /nix/store be trusted.
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
		// A group/world-writable directory is safe when it is sticky: the sticky
		// bit lets only an entry's owner unlink or rename it, so no other user can
		// rename-swap the root-owned config inside it. This is exactly how
		// /nix/store (drwxrwxr-t) and /tmp are protected. Regular files get no
		// such pass — a writable file is rewritten in place — and a non-sticky
		// writable directory allows precisely the rename-swap we guard against.
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

// checkLinkOwner verifies a symlink node itself. Only ownership is checked: a
// symlink's permission bits are ignored by the kernel, so they protect nothing;
// what matters is that only a trusted owner (the user or root) can repoint it.
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

// verifyTrustStore locates the trust store and rejects a directory an attacker
// could tamper with, returning the path so callers reach the store only through
// a location that passed both. A missing store is safe (it holds no grants) and
// is not an error: Trust creates it with 0o700. A store whose location cannot be
// determined at all is a different matter and is refused (see trustDir), since
// the alternative is a working-directory store that any passer-by can seed.
// Callers on the apply path treat any error here as "trust nothing"; Trust
// treats it as a hard refusal.
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
	if err := checkOwnerWritable(dir, fi); err != nil {
		return "", err
	}
	return dir, nil
}

// verifyConfigPath rejects a config an attacker could swap around the moment of
// approval. A regular config is checked along with its parent directory (a
// writable parent lets the file be replaced by rename even when it is
// read-only). A symlinked config (Nix/home-manager) additionally has the link
// node and the resolved target and the target's parent checked, so neither the
// link nor its destination can be repointed or rewritten by an untrusted user.
// Config-side ownership allows the user or root (see trustedOwner).
//
// The guarantee stops at that immediate parent: no higher ancestor is examined,
// so nothing checks who may replace the parent itself. A writable non-sticky
// directory anywhere above lets any user rename the entries inside it, which
// swaps the whole subtree holding the config — the checked parent included —
// for one the attacker controls. The fingerprint bounds only what happens to
// the config bytes after that: a grant is sha256(identity + content), the
// identity is derived from the path, and LoadTrustedConfig re-hashes the bytes
// it is about to apply without re-running any of the checks here. A symlink
// left at the swapped path resolves the identity elsewhere and so misses the
// grant, but a renamed directory keeps the path, and an attacker who copies the
// approved config byte for byte keeps the content too: the grant still matches
// and the config still applies, over a tree that is now theirs, at any time
// after approval. For a config of literal values that leaves the applied env
// exactly as approved; for one whose values dereference the workspace
// ("$WORKSPACE_PATH/bin" on PATH) it hands the attacker's tree to the shell.
// The risk is accepted rather than closed: walking to the filesystem root would
// reject legitimate shared project and home trees, whose upper directories are
// group-writable by policy.
func verifyConfigPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	li, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if li.Mode()&os.ModeSymlink != 0 {
		if err := checkLinkOwner(abs, li); err != nil {
			return err
		}
		if err := checkConfigNode(filepath.Dir(abs)); err != nil {
			return err
		}
		target, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return err
		}
		if err := checkConfigNode(target); err != nil {
			return err
		}
		return checkConfigNode(filepath.Dir(target))
	}
	if err := checkConfigNode(abs); err != nil {
		return err
	}
	return checkConfigNode(filepath.Dir(abs))
}

// canonical resolves path aliases (macOS /tmp -> /private/tmp, symlinked
// checkouts) to one identity: a grant or state recorded through one alias
// must match accesses through any other.
func canonical(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	return abs, nil
}

// configIdentity is a config's logical location: the canonical directory it
// lives in joined with its file name, with the final element deliberately NOT
// symlink-resolved. A config deployed as a symlink (Nix/home-manager) is thus
// identified by where it sits, not where its target happens to point, so a
// store-path change across a rebuild keeps the same identity while an edit to
// the pointed-at bytes still changes the fingerprint. The directory IS resolved,
// so directory aliases (/tmp -> /private/tmp, a symlinked checkout) still map to
// one identity. Reading through this path follows the final symlink, so content
// hashing and parsing see the target's bytes.
func configIdentity(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir, err := canonical(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
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

// IsTrusted answers whether a grant exists for the bytes currently on disk,
// without reading the config for use. Nothing on the apply path calls it, and
// nothing should: asking here and applying afterwards reads the file twice and
// reopens exactly the window LoadTrustedConfig exists to close, so every caller
// that intends to act on the config goes through LoadTrustedConfig instead. It
// stays for callers that only want to inspect grant state without applying it;
// inside this repository those are the tests, which assert what Trust, Untrust
// and Prune left behind.
func IsTrusted(path string) bool {
	// An insecure store means any grant it holds may be forged, and an
	// unlocatable one means there is no store to consult; trust nothing either
	// way.
	dir, err := verifyTrustStore()
	if err != nil {
		return false
	}
	fp, err := fingerprint(path)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, fp))
	return err == nil
}

// LoadTrustedConfig reads the config exactly once, verifies the trust grant
// against those bytes, and parses the very same bytes. Verifying and parsing
// on separate reads would leave a window where the approved content and the
// applied content differ (TOCTOU). The returned fingerprint identifies the
// exact bytes that were applied, so callers can detect an edit even when the
// new content is already trusted again.
func LoadTrustedConfig(path string) (Config, string, error) {
	// A forgeable store invalidates every grant, so refuse before reading the
	// config; the detail is wrapped so callers can match ErrUnsafeTrustStore. A
	// store that cannot be located comes through the same branch on purpose: a
	// grant that cannot be looked up in a trustworthy place is worth no more
	// than one that could have been forged, and the apply path already treats
	// this error as "apply nothing" while still telling the user why.
	dir, err := verifyTrustStore()
	if err != nil {
		return Config{}, "", fmt.Errorf("%w: %v", ErrUnsafeTrustStore, err)
	}
	id, err := configIdentity(path)
	if err != nil {
		return Config{}, "", err
	}
	content, err := readConfigFile(id)
	if err != nil {
		return Config{}, "", err
	}
	fp := fingerprintBytes(id, content)
	if _, err := os.Stat(filepath.Join(dir, fp)); err != nil {
		return Config{}, "", ErrUntrusted
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
	// grant would then vouch for bytes the human never saw. Checks the link and
	// its target when the config is a symlink (see verifyConfigPath).
	if err := verifyConfigPath(path); err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	content, err := readConfigFile(id)
	if err != nil {
		return err
	}
	// Fingerprint before parsing, the same order as LoadTrustedConfig.
	fp := fingerprintBytes(id, content)
	// Approving bytes that cannot be parsed would create a grant the export
	// path can never use, and would warn on every cd instead of failing here.
	if _, err := parseConfig(id, content); err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	// If the store already exists it must be secure before we add a grant to
	// it; a missing store is created below with 0o700. Creating one is also why
	// an unlocatable store has to stop us here rather than fall back to a
	// relative path: the grant would be written into whatever directory the
	// user happened to run the command from.
	dir, err := verifyTrustStore()
	if err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// The record's content is the config identity, for humans inspecting the
	// dir; lookups only ever use the filename. Written via rename: lookups test
	// mere existence, so a crash mid-write must not leave an empty record
	// behind that would pass as a valid grant.
	record := filepath.Join(dir, fp)
	tmp := record + ".tmp"
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, record); err != nil {
		return err
	}
	Ok("trusted %s", id)
	return nil
}

// listTrustStore lists the trust store's records. It is a variable purely so
// tests can reproduce listing failures the filesystem cannot be made to produce
// on demand — a saturated descriptor table, EIO, a stale NFS handle. Those all
// have to be surfaced rather than answered with "not trusted", and a test that
// can only manufacture EACCES cannot pin that down. Production always uses
// os.ReadDir.
var listTrustStore = os.ReadDir

// Untrust matches records by their recorded config identity, not by a
// fingerprint of the current content. A grant is keyed by sha256(identity +
// content), so once the config is edited the current fingerprint no longer names
// any record and the stale grant for the original bytes would survive on disk,
// silently reviving trust the moment the content is restored. Removing every
// record whose recorded identity is the target's logical identity revokes all of
// them, including the one for the content presently on disk.
func Untrust(path string) error {
	// Consistent with the other entry points: surface an insecure or unlocatable
	// store rather than mutating it silently, so the user fixes it before
	// relying on trust. An unlocatable store must not reach the "not trusted"
	// verdict below either: the grant may well exist in the store the user
	// meant, and revocation reporting success-shaped failure is how a live
	// grant survives an untrust the user believes went through.
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
		// No store at all means no grant was ever recorded: this is the ordinary
		// "you never trusted this" case, the same answer as an empty match below.
		return fmt.Errorf("not trusted: %s", path)
	}
	if err != nil {
		// A permission or I/O error is not proof the grant is absent; a store the
		// user cannot list may still hold a live grant. Reporting "not trusted"
		// would send the user looking for the wrong problem, so surface the cause
		// as Prune does.
		return err
	}
	removed := 0
	for _, e := range entries {
		// .tmp leftovers are interrupted writes, not grants; empty records
		// carry no path to match against.
		if strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		// A grant is a file sallyport writes; a directory is somebody else's
		// doing and can never be one, so stepping over it cannot leave a live
		// grant behind. Reading it would fail with EISDIR, which the branch
		// below rightly refuses to ignore, and one stray directory would then
		// make every untrust impossible.
		if e.IsDir() {
			continue
		}
		record := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(record)
		if os.IsNotExist(err) {
			// A concurrent untrust or prune won the race: the record is gone,
			// so it holds no grant to revoke.
			continue
		}
		if err != nil {
			// The same reasoning as the listing above, one level down. A record
			// that cannot be read may be the very grant being revoked, so
			// skipping it would leave trust in force while the command reports
			// "not trusted" and exits as if there were nothing to do.
			return err
		}
		if strings.TrimSpace(string(data)) != target {
			continue
		}
		// A concurrent untrust or prune may have removed the record first;
		// the goal (no grant on disk) is met either way.
		if err := os.Remove(record); err != nil && !os.IsNotExist(err) {
			return err
		}
		removed++
	}
	if removed == 0 {
		return fmt.Errorf("not trusted: %s", path)
	}
	Ok("untrusted %s", target)
	return nil
}

// Prune removes grants whose recorded config file no longer exists, plus
// leftovers of interrupted writes. Grants for edited configs are kept on
// purpose: restoring the original bytes legitimately revives them.
func Prune() error {
	// Consistent with the other entry points: surface an insecure or unlocatable
	// store rather than mutating it silently, so the user fixes it before
	// relying on trust.
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
			// Only an interrupted write by an older version leaves an empty
			// record; it can never be matched intentionally.
			if err := os.Remove(record); err != nil && !os.IsNotExist(err) {
				return err
			}
			removed++
			continue
		}
		if _, err := os.Stat(path); err != nil {
			if !os.IsNotExist(err) {
				// A permission or I/O error is not proof the config is gone;
				// removing the grant on a guess would revoke a still-valid one.
				// Surface it and keep the record so the user can act.
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
