package workspace

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newWorkspaceDir(t *testing.T, config string) string {
	t.Helper()
	root := newUntrustedWorkspaceDir(t, config)
	if err := Trust(ConfigPath(root)); err != nil {
		t.Fatal(err)
	}
	return root
}

func newUntrustedWorkspaceDir(t *testing.T, config string) string {
	t.Helper()
	// Isolate the trust store, but only once per test: rotating it on every
	// call would drop grants of workspaces created earlier in the same test.
	if cur := os.Getenv("XDG_DATA_HOME"); cur == "" || !strings.HasPrefix(cur, os.TempDir()) {
		t.Setenv("XDG_DATA_HOME", t.TempDir())
	}
	root := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, root, config)
	return root
}

func stateFromScript(t *testing.T, script string) state {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		raw, found := strings.CutPrefix(line, "export "+stateEnvKey+"='")
		if !found {
			continue
		}
		raw = strings.TrimSuffix(raw, "'")
		data, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			t.Fatalf("decode state: %v", err)
		}
		var s state
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatalf("unmarshal state: %v", err)
		}
		return s
	}
	t.Fatalf("no %s in script:\n%s", stateEnvKey, script)
	return state{}
}

func setState(t *testing.T, s state) {
	t.Helper()
	encoded, err := encodeState(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(stateEnvKey, encoded)
}

func TestExportEnterSavesOriginals(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	t.Setenv("SSH_AUTH_SOCK", "/original/agent.sock")
	t.Setenv("WORKSPACE_PATH", "placeholder")
	os.Unsetenv("WORKSPACE_PATH")
	root := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/1password/agent.sock"}}`)

	script, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"export WORKSPACE_PATH='" + root + "'",
		"export SSH_AUTH_SOCK='/1password/agent.sock'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
	st := stateFromScript(t, script)
	if st.Root != root {
		t.Errorf("state root = %q, want %q", st.Root, root)
	}
	if got := st.Saved["SSH_AUTH_SOCK"]; got == nil || *got != "/original/agent.sock" {
		t.Errorf("original SSH_AUTH_SOCK not saved: %v", got)
	}
	if got, hit := st.Saved["WORKSPACE_PATH"]; !hit || got != nil {
		t.Errorf("unset WORKSPACE_PATH should be saved as nil, got %v (hit=%v)", got, hit)
	}
}

func TestExportNoopWithinSameWorkspace(t *testing.T) {
	root := newWorkspaceDir(t, `{"env": {}}`)
	setState(t, state{Root: root, Saved: map[string]*string{}})

	script, err := BuildExportScript(filepath.Join(root, "repo", "sub"), false)
	if err != nil {
		t.Fatal(err)
	}
	if script != "" {
		t.Errorf("expected empty script, got:\n%s", script)
	}
}

func TestExportLeaveRestoresOriginals(t *testing.T) {
	orig := "/original/agent.sock"
	setState(t, state{
		Root: "/somewhere/demo",
		Saved: map[string]*string{
			"SSH_AUTH_SOCK":  &orig,
			"WORKSPACE_PATH": nil,
		},
	})

	script, err := BuildExportScript(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"export SSH_AUTH_SOCK='/original/agent.sock'",
		"unset WORKSPACE_PATH",
		"unset " + stateEnvKey,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
}

func TestExportSwitchKeepsPreWorkspaceOriginals(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	t.Setenv("SSH_AUTH_SOCK", "/original/agent.sock")
	rootA := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/a/agent.sock"}}`)
	rootB := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/b/agent.sock"}}`)

	enterA, err := BuildExportScript(rootA, false)
	if err != nil {
		t.Fatal(err)
	}
	stA := stateFromScript(t, enterA)

	// Simulate the shell having applied workspace a.
	setState(t, stA)
	t.Setenv("SSH_AUTH_SOCK", "/a/agent.sock")
	t.Setenv("WORKSPACE_PATH", rootA)

	enterB, err := BuildExportScript(rootB, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(enterB, "export SSH_AUTH_SOCK='/b/agent.sock'") {
		t.Errorf("switch does not apply workspace b:\n%s", enterB)
	}
	stB := stateFromScript(t, enterB)
	if got := stB.Saved["SSH_AUTH_SOCK"]; got == nil || *got != "/original/agent.sock" {
		t.Errorf("pre-workspace original lost on switch: %v", got)
	}
}

func TestExportIgnoresBrokenConfig(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newUntrustedWorkspaceDir(t, `{"env": {"$(whoami)": "x"}}`)
	// Trust refuses unparseable configs, so forge the grant directly to
	// simulate bytes approved by an older version with different parse rules.
	abs, err := filepath.Abs(ConfigPath(root))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(trustDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustDir(), fingerprintBytes(abs, content)), []byte(abs+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	script, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "whoami") {
		t.Errorf("broken config leaked into eval'd output:\n%s", script)
	}
	// The transition must still be recorded, or the hook would retry (and
	// re-warn) on every cd inside the workspace.
	if st := stateFromScript(t, script); st.Root != root {
		t.Errorf("state root = %q, want %q", st.Root, root)
	}
}

func TestExportSkipsUntrustedConfig(t *testing.T) {
	orig := "/original/agent.sock"
	root := newUntrustedWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/evil/agent.sock"}}`)
	setState(t, state{Root: "/previous/demo", Saved: map[string]*string{"SSH_AUTH_SOCK": &orig}})

	script, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "evil") {
		t.Errorf("untrusted config was applied:\n%s", script)
	}
	// The previous workspace must still be rolled back.
	for _, want := range []string{
		"export SSH_AUTH_SOCK='/original/agent.sock'",
		"unset " + stateEnvKey,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
}

func TestExportTrustExpiresOnEdit(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "good"}}`)
	writeConfig(t, root, `{"env": {"OP_ACCOUNT": "tampered"}}`)

	script, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "tampered") {
		t.Errorf("edited config kept its trust grant:\n%s", script)
	}
}

func TestExportUntrustInPlaceRollsBack(t *testing.T) {
	orig := "/original/agent.sock"
	root := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/1password/agent.sock"}}`)
	setState(t, state{Root: root, Saved: map[string]*string{"SSH_AUTH_SOCK": &orig}})

	if err := Untrust(ConfigPath(root)); err != nil {
		t.Fatal(err)
	}
	// Same pwd, no cd: revocation must roll the environment back anyway.
	script, err := BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"export SSH_AUTH_SOCK='/original/agent.sock'",
		"unset " + stateEnvKey,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
}

func TestExportTrustInPlaceApplies(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newUntrustedWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "late.example.com"}}`)

	script, err := BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "late.example.com") {
		t.Fatalf("applied before trust:\n%s", script)
	}

	if err := Trust(ConfigPath(root)); err != nil {
		t.Fatal(err)
	}
	// Same pwd, no cd: the very next evaluation must apply the workspace.
	script, err = BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "export OP_ACCOUNT='late.example.com'") {
		t.Errorf("trust did not take effect without a cd:\n%s", script)
	}
}

// The state export must be the final line: if the emitting process dies
// mid-write, the shell evals a script whose state was never committed, and
// the next evaluation simply redoes the whole (idempotent) transition.
func TestExportCommitsStateLast(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/1password/agent.sock"}}`)

	script, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(script, "\n"), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "export "+stateEnvKey+"=") {
		t.Errorf("state is not committed last: %q", last)
	}
}

func TestZshQuote(t *testing.T) {
	cases := map[string]string{
		"plain":        "'plain'",
		"with space":   "'with space'",
		"single'quote": `'single'\''quote'`,
	}
	for in, want := range cases {
		if got := zshQuote(in); got != want {
			t.Errorf("zshQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
