package workspace

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// quoteJSON emits a JSON string literal. It has to be a real JSON encoder:
// strconv.Quote's escape alphabet is not JSON's (\x00 has no JSON spelling), so
// a test payload carrying a control character would fail on syntax instead of
// on what it means to test.
func quoteJSON(s string) string {
	// Marshaling a string cannot fail.
	b, _ := json.Marshal(s)
	return string(b)
}

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
		// The key goes through quoteJSON: pasted raw, a key containing a quote or
		// a newline would break the JSON itself and the test would pass on a
		// syntax error instead of on key validation.
		writeConfig(t, dir, `{"env": {`+quoteJSON(key)+`: "x"}}`)
		_, err := LoadConfig(ConfigPath(dir))
		if err == nil {
			t.Errorf("env key %q accepted, want error", key)
			continue
		}
		if !strings.Contains(err.Error(), "invalid env key") {
			t.Errorf("env key %q rejected for the wrong reason: %v", key, err)
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

func TestLoadConfigExpandRejectsUnquotableValue(t *testing.T) {
	// In expand mode the value is emitted verbatim inside `export KEY="..."`, so
	// content that cannot be a double-quoted body fails the whole eval.
	cases := map[string]string{
		"unescaped double quote": `a"b`,
		"trailing backslash":     `abc\`,
		"only a backslash":       `\`,
	}
	for name, val := range cases {
		dir := t.TempDir()
		writeConfig(t, dir, `{"expand": true, "env": {"FOO": `+quoteJSON(val)+`}}`)
		if _, err := LoadConfig(ConfigPath(dir)); err == nil {
			t.Errorf("%s: value %q accepted under expand, want error", name, val)
		}
	}
}

func TestLoadConfigExpandAcceptsEscapedValue(t *testing.T) {
	// Properly escaped sequences are legal double-quoted source text.
	dir := t.TempDir()
	writeConfig(t, dir, `{"expand": true, "env": {"FOO": `+quoteJSON(`a\"b\\c`)+`}}`)
	cfg, err := LoadConfig(ConfigPath(dir))
	if err != nil {
		t.Fatalf("escaped value rejected: %v", err)
	}
	if cfg.Env["FOO"] != `a\"b\\c` {
		t.Errorf("FOO = %q", cfg.Env["FOO"])
	}
}

func TestLoadConfigStrictModeAcceptsAnyValue(t *testing.T) {
	// Strict mode single-quotes values, so content that would be illegal inside
	// double quotes is carried safely.
	for _, val := range []string{`a"b`, `abc\`, `\`, `$(whoami)`} {
		dir := t.TempDir()
		writeConfig(t, dir, `{"env": {"FOO": `+quoteJSON(val)+`}}`)
		cfg, err := LoadConfig(ConfigPath(dir))
		if err != nil {
			t.Errorf("strict mode rejected %q: %v", val, err)
			continue
		}
		if cfg.Env["FOO"] != val {
			t.Errorf("FOO = %q, want %q", cfg.Env["FOO"], val)
		}
	}
}

// wantMaxConfigSize is the size limit spelled out independently of
// maxConfigSize, so that raising or dropping the limit fails these tests
// instead of moving with them.
const wantMaxConfigSize = 1 << 20

// writeConfigOfSize writes a valid config whose encoded form is exactly n bytes.
func writeConfigOfSize(t *testing.T, dir string, n int) {
	t.Helper()
	const prefix, suffix = `{"env": {"PAD": "`, `"}}`
	if n < len(prefix)+len(suffix) {
		t.Fatalf("size %d is below the smallest config", n)
	}
	writeConfig(t, dir, prefix+strings.Repeat("x", n-len(prefix)-len(suffix))+suffix)
}

func TestLoadConfigRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	writeConfigOfSize(t, dir, wantMaxConfigSize+1)
	_, err := LoadConfig(ConfigPath(dir))
	if err == nil {
		t.Fatal("oversized config accepted, want error")
	}
	// The payload is well-formed, and the message must name the size limit: an
	// error for any other reason would let the limit be raised or removed
	// without this test noticing.
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want the size limit to be the reason", err)
	}
}

func TestLoadConfigAcceptsFileAtSizeLimit(t *testing.T) {
	// The boundary itself is legal: exactly the limit must still load.
	dir := t.TempDir()
	writeConfigOfSize(t, dir, wantMaxConfigSize)
	cfg, err := LoadConfig(ConfigPath(dir))
	if err != nil {
		t.Fatalf("config of exactly %d bytes rejected: %v", wantMaxConfigSize, err)
	}
	if cfg.Env["PAD"] == "" {
		t.Error("config at the size limit parsed without its env entry")
	}
}

// TestReadConfigFileEnforcesSizeLimit pins where and how the limit is applied,
// not just its value: Trust and LoadTrustedConfig call readConfigFile directly,
// symlinked configs are a supported deployment shape, and the limit exists to
// bound the per-prompt cost, which only holds if the file is never read.
func TestReadConfigFileEnforcesSizeLimit(t *testing.T) {
	dir := t.TempDir()
	writeConfigOfSize(t, dir, wantMaxConfigSize+1)
	path := ConfigPath(dir)

	wantRefusal := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("oversized config accepted, want error")
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("error = %v, want the size limit to be the reason", err)
		}
	}

	t.Run("on the readConfigFile path", func(t *testing.T) {
		_, err := readConfigFile(path)
		wantRefusal(t, err)
	})

	t.Run("through a symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), ConfigFileName)
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		_, err := readConfigFile(link)
		wantRefusal(t, err)
	})

	t.Run("without reading the file", func(t *testing.T) {
		// The size is answered from the descriptor's own stat, so a file far
		// larger than the limit costs an open and nothing more. Reading it to
		// find out would be the whole cost the limit exists to avoid.
		big := t.TempDir()
		huge := ConfigPath(big)
		f, err := os.Create(huge)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(1 << 30); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, err = readConfigFile(huge)
		wantRefusal(t, err)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("refusing a 1 GiB config took %v; the limit is meant to be answered without reading", elapsed)
		}
	})
}

func TestParseConfigLeavesInputUnmodified(t *testing.T) {
	// hujson.Standardize rewrites its input buffer in place. Callers fingerprint
	// the very bytes they hand to parseConfig, so a parse that mutated them would
	// make the recorded fingerprint depend on parse order. Sizes vary because a
	// copy taken only for small inputs would still corrupt real configs.
	for _, pad := range []int{0, 8000} {
		src := []byte("{\n  // comment\n  \"env\": {\"FOO\": \"" + strings.Repeat("x", pad) + "\"}, // trailing\n}\n")
		want := append([]byte(nil), src...)
		if _, err := parseConfig("cfg.jsonc", src); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(src, want) {
			t.Errorf("parseConfig modified its %d-byte input", len(want))
		}
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
	// Resolved because FindRoot answers with the directories the kernel names,
	// and t.TempDir hands back an alias on macOS.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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

// A .sallyport.jsonc symlinked to a regular file marks a workspace: Nix and
// home-manager deploy configs as symlinks into a read-only store.
func TestFindRootFollowsSymlinkToRegularFile(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	regRoot := filepath.Join(base, "regular")
	if err := os.MkdirAll(regRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "store-config")
	if err := os.WriteFile(target, []byte(`{"env": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(regRoot, ConfigFileName)); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(regRoot); got != regRoot {
		t.Errorf("symlink to regular file: FindRoot = %q, want %q", got, regRoot)
	}

	dirRoot := filepath.Join(base, "todir")
	if err := os.MkdirAll(dirRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(dirRoot, ConfigFileName)); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(dirRoot); got != "" {
		t.Errorf("symlink to directory: FindRoot = %q, want empty", got)
	}

	danglingRoot := filepath.Join(base, "dangling")
	if err := os.MkdirAll(danglingRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "does-not-exist"), filepath.Join(danglingRoot, ConfigFileName)); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(danglingRoot); got != "" {
		t.Errorf("dangling symlink: FindRoot = %q, want empty", got)
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
		{Key: "WORKSPACE_PATH", Val: dir, Literal: true},
		{Key: "A_KEY", Val: "a", Literal: true},
		{Key: "B_KEY", Val: "b", Literal: true},
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

func TestWorkspaceVarsExpandMakesValuesNonLiteral(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `{"expand": true, "env": {"A_KEY": "a"}}`)

	cfg, err := LoadConfig(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	vars := WorkspaceVars(dir, cfg)
	// The automatic WORKSPACE_PATH stays literal even in expand mode.
	want := []EnvVar{
		{Key: "WORKSPACE_PATH", Val: dir, Literal: true},
		{Key: "A_KEY", Val: "a", Literal: false},
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
	if len(vars) != 1 || vars[0] != (EnvVar{Key: "WORKSPACE_PATH", Val: "/custom", Literal: true}) {
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
