package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrUntrusted marks a config that exists but has no valid trust grant.
var ErrUntrusted = errors.New("config is not trusted")

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

func fingerprint(path string) (string, error) {
	abs, err := filepath.Abs(path)
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
// applied content differ (TOCTOU).
func LoadTrustedConfig(path string) (Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	content, err := readConfigFile(abs)
	if err != nil {
		return Config{}, err
	}
	fp := fingerprintBytes(abs, content)
	if _, err := os.Stat(filepath.Join(trustDir(), fp)); err != nil {
		return Config{}, ErrUntrusted
	}
	return parseConfig(abs, content)
}

func Trust(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
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

func Untrust(path string) error {
	fp, err := fingerprint(path)
	if err != nil {
		return err
	}
	record := filepath.Join(trustDir(), fp)
	if _, err := os.Stat(record); err != nil {
		return fmt.Errorf("not trusted: %s", path)
	}
	if err := os.Remove(record); err != nil {
		return err
	}
	Ok("untrusted %s", path)
	return nil
}
