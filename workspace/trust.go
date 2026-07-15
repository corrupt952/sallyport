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

// Trust records approvals as sha256(config path + content), so any edit to an
// approved config silently revokes the grant. Without this, cd-ing into a
// cloned repository would apply attacker-controlled env vars (PATH included).

func trustDir() string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		h, _ := os.UserHomeDir()
		base = filepath.Join(h, ".local", "share")
	}
	return filepath.Join(base, "sallyport", "trust")
}

// checkOwnerWritable rejects a path not owned by the current user or writable
// by group or other. Those are precisely the conditions under which someone
// else could substitute its contents between the moment a grant is recorded
// (or verified) and the moment sallyport acts on it. The error carries the fix
// so the user is not left guessing.
func checkOwnerWritable(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// Non-unix Sys() shape: we cannot prove ownership, so we cannot vouch
		// for the path. sallyport only targets unix shells, so this is a guard
		// against the impossible rather than an expected path.
		return fmt.Errorf("%s: cannot determine owner", path)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not you (uid %d); chown it to yourself", path, st.Uid, os.Getuid())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by others; run: chmod go-w %s", path, path)
	}
	return nil
}

// verifyTrustStore rejects a trust directory an attacker could tamper with. A
// missing store is safe (it holds no grants) and is not an error: Trust creates
// it with 0o700. Callers on the apply path treat any error here as "trust
// nothing"; Trust treats it as a hard refusal.
func verifyTrustStore() error {
	dir := trustDir()
	fi, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s exists but is not a directory; remove it", dir)
	}
	return checkOwnerWritable(dir, fi)
}

// verifyConfigPath rejects a config whose file or containing directory is owned
// by someone else or writable by group/other. Either lets an attacker swap the
// bytes a human reviewed for hostile ones around the moment of approval: a
// writable file is rewritten in place, a writable parent is swapped by rename
// even when the file itself is read-only. The grant is keyed by the reviewed
// content, so both must be locked down before trusting.
func verifyConfigPath(abs string) error {
	fi, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if err := checkOwnerWritable(abs, fi); err != nil {
		return err
	}
	parent := filepath.Dir(abs)
	pfi, err := os.Stat(parent)
	if err != nil {
		return err
	}
	return checkOwnerWritable(parent, pfi)
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

func fingerprint(path string) (string, error) {
	abs, err := canonical(path)
	if err != nil {
		return "", err
	}
	content, err := readConfigFile(abs)
	if err != nil {
		return "", err
	}
	return fingerprintBytes(abs, content), nil
}

func fingerprintBytes(abs string, content []byte) string {
	h := sha256.New()
	h.Write([]byte(abs))
	h.Write([]byte{0})
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

func IsTrusted(path string) bool {
	// An insecure store means any grant it holds may be forged; trust nothing.
	if verifyTrustStore() != nil {
		return false
	}
	fp, err := fingerprint(path)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(trustDir(), fp))
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
	// config; the detail is wrapped so callers can match ErrUnsafeTrustStore.
	if err := verifyTrustStore(); err != nil {
		return Config{}, "", fmt.Errorf("%w: %v", ErrUnsafeTrustStore, err)
	}
	abs, err := canonical(path)
	if err != nil {
		return Config{}, "", err
	}
	content, err := readConfigFile(abs)
	if err != nil {
		return Config{}, "", err
	}
	fp := fingerprintBytes(abs, content)
	if _, err := os.Stat(filepath.Join(trustDir(), fp)); err != nil {
		return Config{}, "", ErrUntrusted
	}
	cfg, err := parseConfig(abs, content)
	return cfg, fp, err
}

func Trust(path string) error {
	abs, err := canonical(path)
	if err != nil {
		return err
	}
	// Reject a config someone else could swap between review and approval: the
	// grant would then vouch for bytes the human never saw.
	if err := verifyConfigPath(abs); err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	content, err := readConfigFile(abs)
	if err != nil {
		return err
	}
	// Fingerprint before parsing, the same order as LoadTrustedConfig.
	fp := fingerprintBytes(abs, content)
	// Approving bytes that cannot be parsed would create a grant the export
	// path can never use, and would warn on every cd instead of failing here.
	if _, err := parseConfig(abs, content); err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	// If the store already exists it must be secure before we add a grant to
	// it; a missing store is created below with 0o700.
	if err := verifyTrustStore(); err != nil {
		return fmt.Errorf("refusing to trust: %w", err)
	}
	if err := os.MkdirAll(trustDir(), 0o700); err != nil {
		return err
	}
	// The record's content is the config path, for humans inspecting the dir;
	// lookups only ever use the filename. Written via rename: lookups test
	// mere existence, so a crash mid-write must not leave an empty record
	// behind that would pass as a valid grant.
	record := filepath.Join(trustDir(), fp)
	tmp := record + ".tmp"
	if err := os.WriteFile(tmp, []byte(abs+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, record); err != nil {
		return err
	}
	Ok("trusted %s", abs)
	return nil
}

// Untrust matches records by their recorded config path, not by a fingerprint
// of the current content. A grant is keyed by sha256(path + content), so once
// the config is edited the current fingerprint no longer names any record and
// the stale grant for the original bytes would survive on disk, silently
// reviving trust the moment the content is restored. Removing every record
// whose recorded path is the target's canonical path revokes all of them,
// including the one for the content presently on disk.
func Untrust(path string) error {
	// Consistent with the other entry points: surface an insecure store rather
	// than mutating it silently, so the user fixes it before relying on trust.
	if err := verifyTrustStore(); err != nil {
		return fmt.Errorf("refusing to untrust: %w", err)
	}
	target, err := canonical(path)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(trustDir())
	if err != nil {
		return fmt.Errorf("not trusted: %s", path)
	}
	removed := 0
	for _, e := range entries {
		// .tmp leftovers are interrupted writes, not grants; empty records
		// carry no path to match against.
		if strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		record := filepath.Join(trustDir(), e.Name())
		data, err := os.ReadFile(record)
		if err != nil {
			continue
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
	// Consistent with the other entry points: surface an insecure store rather
	// than mutating it silently, so the user fixes it before relying on trust.
	if err := verifyTrustStore(); err != nil {
		return fmt.Errorf("refusing to prune: %w", err)
	}
	entries, err := os.ReadDir(trustDir())
	if os.IsNotExist(err) {
		Info("nothing to prune")
		return nil
	}
	if err != nil {
		return err
	}
	removed := 0
	for _, e := range entries {
		record := filepath.Join(trustDir(), e.Name())
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
