package workspace

import (
	"errors"
	"path/filepath"
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
	if err := Untrust(path); err == nil {
		t.Fatal("expected error when untrusting an unapproved config")
	}
}

func TestLoadTrustedConfig(t *testing.T) {
	path := trustSetup(t)

	if _, err := LoadTrustedConfig(path); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("unapproved config: got %v, want ErrUntrusted", err)
	}
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustedConfig(path); err != nil {
		t.Fatalf("approved config rejected: %v", err)
	}

	writeConfig(t, filepath.Dir(path), `{"env": {"ADDED": "later"}}`)
	if _, err := LoadTrustedConfig(path); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("edited config: got %v, want ErrUntrusted", err)
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
