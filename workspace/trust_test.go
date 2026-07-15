package workspace

import (
	"errors"
	"os"
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

	if _, _, err := LoadTrustedConfig(path); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("unapproved config: got %v, want ErrUntrusted", err)
	}
	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	if _, fp, err := LoadTrustedConfig(path); err != nil {
		t.Fatalf("approved config rejected: %v", err)
	} else if fp == "" {
		t.Fatal("approved config returned no fingerprint")
	}

	writeConfig(t, filepath.Dir(path), `{"env": {"ADDED": "later"}}`)
	if _, _, err := LoadTrustedConfig(path); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("edited config: got %v, want ErrUntrusted", err)
	}
}

func TestTrustViaAliasPath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	real := t.TempDir()
	writeConfig(t, real, `{"env": {}}`)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if err := Trust(ConfigPath(link)); err != nil {
		t.Fatal(err)
	}
	if !IsTrusted(ConfigPath(real)) {
		t.Error("grant via alias does not cover the canonical path")
	}
	if !IsTrusted(ConfigPath(link)) {
		t.Error("grant via alias does not cover the alias itself")
	}
}

func TestUntrustAfterEditRemovesStaleGrant(t *testing.T) {
	path := trustSetup(t)
	original := `{"env": {}}`

	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	// Editing the config leaves the grant for the original bytes on disk while
	// changing the current fingerprint; Untrust must still find and remove it.
	writeConfig(t, filepath.Dir(path), `{"env": {"ADDED": "later"}}`)
	if err := Untrust(path); err != nil {
		t.Fatalf("untrust after edit failed: %v", err)
	}

	// Restoring the original content must not revive trust: the stale grant is
	// gone, so this is the regression that motivated matching records by path.
	writeConfig(t, filepath.Dir(path), original)
	if IsTrusted(path) {
		t.Fatal("trust revived after restoring content of an untrusted config")
	}
}

func TestPruneRemovesTmpAndEmptyRecords(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {}}`)
	if err := Trust(ConfigPath(dir)); err != nil {
		t.Fatal(err)
	}
	// A crashed write of an older version can leave a .tmp leftover and an
	// empty record; both must be pruned while the real grant survives.
	if err := os.WriteFile(filepath.Join(trustDir(), "leftover.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustDir(), "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Prune(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(trustDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d records after prune, want 1", len(entries))
	}
	if !IsTrusted(ConfigPath(dir)) {
		t.Error("prune removed a grant whose config still exists")
	}
}

func TestPruneRemovesStaleRecords(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	kept := t.TempDir()
	writeConfig(t, kept, `{"env": {}}`)
	gone := t.TempDir()
	writeConfig(t, gone, `{"env": {}}`)
	for _, p := range []string{ConfigPath(kept), ConfigPath(gone)} {
		if err := Trust(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(ConfigPath(gone)); err != nil {
		t.Fatal(err)
	}

	if err := Prune(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(trustDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d records after prune, want 1", len(entries))
	}
	if !IsTrusted(ConfigPath(kept)) {
		t.Error("prune removed a grant whose config still exists")
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
