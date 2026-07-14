package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

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
	content, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(abs))
	h.Write([]byte{0})
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func IsTrusted(path string) bool {
	fp, err := fingerprint(path)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(trustDir(), fp))
	return err == nil
}

func Trust(path string) error {
	fp, err := fingerprint(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(trustDir(), 0o700); err != nil {
		return err
	}
	// The record's content is the config path, for humans inspecting the dir;
	// lookups only ever use the filename.
	abs, _ := filepath.Abs(path)
	if err := os.WriteFile(filepath.Join(trustDir(), fp), []byte(abs+"\n"), 0o600); err != nil {
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
