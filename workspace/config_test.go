package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ConfigFileName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigAcceptsCommentsAndTrailingCommas(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `{
  // comment
  "env": {
    "SSH_AUTH_SOCK": "/path/with space/agent.sock", // trailing comment
    "OP_ACCOUNT": "example.1password.com",
  },
}
`)
	cfg, err := LoadConfig(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Env["SSH_AUTH_SOCK"] != "/path/with space/agent.sock" {
		t.Errorf("SSH_AUTH_SOCK = %q", cfg.Env["SSH_AUTH_SOCK"])
	}
	if cfg.Env["OP_ACCOUNT"] != "example.1password.com" {
		t.Errorf("OP_ACCOUNT = %q", cfg.Env["OP_ACCOUNT"])
	}
}

func TestLoadConfigRejectsInvalidEnvKey(t *testing.T) {
	for _, key := range []string{"; rm -rf ~ #", "FOO BAR", "$(whoami)", "A-B"} {
		dir := t.TempDir()
		writeConfig(t, dir, `{"env": {"`+key+`": "x"}}`)
		if _, err := LoadConfig(ConfigPath(dir)); err == nil {
			t.Errorf("env key %q accepted, want error", key)
		}
	}
}

func TestLoadConfigRejectsNonStringValue(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {"PORT": 8080}}`)
	if _, err := LoadConfig(ConfigPath(dir)); err == nil {
		t.Error("non-string env value accepted, want error")
	}
}

func TestLoadConfigRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	huge := append(make([]byte, 0, maxConfigSize+64), `{"env": {}}`...)
	huge = append(huge, make([]byte, maxConfigSize)...)
	if err := os.WriteFile(filepath.Join(dir, ConfigFileName), huge, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(ConfigPath(dir)); err == nil {
		t.Error("oversized config accepted, want error")
	}
}

func TestLoadConfigRejectsBrokenSyntax(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `{env: broken`)
	if _, err := LoadConfig(ConfigPath(dir)); err == nil {
		t.Error("broken config accepted, want error")
	}
}

func TestFindRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "demo")
	nested := filepath.Join(root, "repo", "sub")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, root, `{"env": {}}`)

	if got := FindRoot(nested); got != root {
		t.Errorf("FindRoot(nested) = %q, want %q", got, root)
	}
	if got := FindRoot(root); got != root {
		t.Errorf("FindRoot(root) = %q, want %q", got, root)
	}
	if got := FindRoot(base); got != "" {
		t.Errorf("FindRoot(outside) = %q, want empty", got)
	}
}

func TestFindRootIgnoresSymlinkedConfig(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "elsewhere")
	if err := os.WriteFile(target, []byte(`{"env": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, ConfigFileName)); err != nil {
		t.Fatal(err)
	}

	if got := FindRoot(root); got != "" {
		t.Errorf("FindRoot followed a symlinked config: %q", got)
	}
}

func TestWorkspaceVars(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {"B_KEY": "b", "A_KEY": "a"}}`)

	cfg, err := LoadConfig(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	vars := WorkspaceVars(dir, cfg)
	want := []EnvVar{
		{Key: "WORKSPACE_PATH", Val: dir},
		{Key: "A_KEY", Val: "a"},
		{Key: "B_KEY", Val: "b"},
	}
	if len(vars) != len(want) {
		t.Fatalf("got %v, want %v", vars, want)
	}
	for i := range want {
		if vars[i] != want[i] {
			t.Errorf("vars[%d] = %v, want %v", i, vars[i], want[i])
		}
	}
}

func TestWorkspaceVarsExplicitWorkspacePathWins(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {"WORKSPACE_PATH": "/custom"}}`)

	cfg, err := LoadConfig(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	vars := WorkspaceVars(dir, cfg)
	if len(vars) != 1 || vars[0] != (EnvVar{Key: "WORKSPACE_PATH", Val: "/custom"}) {
		t.Errorf("got %v, want single custom WORKSPACE_PATH", vars)
	}
}

func TestCreateWritesLoadableTemplate(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	if err := Create(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(ConfigPath(dir))
	if err != nil {
		t.Fatalf("generated template does not load: %v", err)
	}
	if len(cfg.Env) != 0 {
		t.Errorf("template env should be empty, got %v", cfg.Env)
	}
}

func TestCreateRefusesOverwrite(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir, `{"env": {"KEEP": "me"}}`)
	if err := Create(dir); err == nil {
		t.Error("expected error when .sallyport.jsonc already exists")
	}
	cfg, err := LoadConfig(ConfigPath(dir))
	if err != nil || cfg.Env["KEEP"] != "me" {
		t.Errorf("existing config was clobbered: %v, %v", cfg, err)
	}
}
