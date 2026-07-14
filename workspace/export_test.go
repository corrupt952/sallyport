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

	script, err := BuildExportScript(root)
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

	script, err := BuildExportScript(filepath.Join(root, "repo", "sub"))
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

	script, err := BuildExportScript(t.TempDir())
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

	enterA, err := BuildExportScript(rootA)
	if err != nil {
		t.Fatal(err)
	}
	stA := stateFromScript(t, enterA)

	// Simulate the shell having applied workspace a.
	setState(t, stA)
	t.Setenv("SSH_AUTH_SOCK", "/a/agent.sock")
	t.Setenv("WORKSPACE_PATH", rootA)

	enterB, err := BuildExportScript(rootB)
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
	root := newWorkspaceDir(t, `{"env": {"$(whoami)": "x"}}`)

	script, err := BuildExportScript(root)
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
