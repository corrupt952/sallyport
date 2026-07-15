package workspace

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
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
	// State roots are canonical, and macOS puts TMPDIR behind a symlink
	// (/var -> /private/var), so expected values must be canonical too.
	if c, err := filepath.EvalSymlinks(root); err == nil {
		root = c
	}
	writeConfig(t, root, config)
	return root
}

func stateFromScript(t *testing.T, script string) state {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		raw, found := strings.CutPrefix(line, "typeset -g "+stateShellVar+"='")
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
	t.Fatalf("no %s in script:\n%s", stateShellVar, script)
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
		`export SSH_AUTH_SOCK="/1password/agent.sock"`,
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

// configFingerprint mirrors the fingerprint of root's config as
// LoadTrustedConfig would compute it, for building applied states in tests.
func configFingerprint(t *testing.T, root string) string {
	t.Helper()
	fp, err := fingerprint(ConfigPath(root))
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func TestExportNoopWithinSameWorkspace(t *testing.T) {
	root := newWorkspaceDir(t, `{"env": {}}`)
	setState(t, state{Root: root, Fingerprint: configFingerprint(t, root), Saved: map[string]*string{}})

	if err := os.MkdirAll(filepath.Join(root, "repo", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
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
		"typeset -g " + stateShellVar + "=''",
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
	if !strings.Contains(enterB, `export SSH_AUTH_SOCK="/b/agent.sock"`) {
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
		"typeset -g " + stateShellVar + "=''",
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
		"typeset -g " + stateShellVar + "=''",
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
	if !strings.Contains(script, `export OP_ACCOUNT="late.example.com"`) {
		t.Errorf("trust did not take effect without a cd:\n%s", script)
	}
}

// The shim must not invoke the hook while .zshrc is still being sourced:
// later export lines would clobber applied values and be recorded as the
// values to restore. Application belongs to the first precmd.
func TestZshHookRegistersWithoutApplying(t *testing.T) {
	script, err := ZshHook()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.TrimSpace(line) == "_sallyport_hook" {
			t.Fatalf("shim applies immediately:\n%s", script)
		}
	}
}

// The shim must keep the state non-exported and pass it to the binary only
// as a one-shot, invocation-scoped env var: an exported state would be
// inherited by every child process the workspace starts.
func TestZshHookPassesStateAsOneShotEnvVar(t *testing.T) {
	script, err := ZshHook()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "typeset -g "+stateShellVar) {
		t.Errorf("shim does not declare a non-exported state global:\n%s", script)
	}
	if !strings.Contains(script, stateEnvKey+`="${`+stateShellVar+`-}"`) {
		t.Errorf("shim does not pass state as a one-shot env var to the binary invocation:\n%s", script)
	}
	if strings.Contains(script, "export "+stateEnvKey) {
		t.Errorf("shim exports the state:\n%s", script)
	}
}

// Entering through a path alias must resolve to the same identity as the
// canonical path: no re-trust prompt, no enter/leave churn between aliases.
func TestExportSymlinkedPwdMatchesCanonical(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "alias.example.com"}}`)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}

	script, err := BuildExportScript(link, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `export OP_ACCOUNT="alias.example.com"`) {
		t.Fatalf("symlinked entry did not apply:\n%s", script)
	}
	st := stateFromScript(t, script)
	if st.Root != root {
		t.Errorf("state root = %q, want canonical %q", st.Root, root)
	}

	// Moving to the canonical path afterwards must be a no-op.
	setState(t, st)
	script, err = BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if script != "" {
		t.Errorf("alias switch caused churn:\n%s", script)
	}
}

// An edit that gets re-trusted between two prompts must reapply: only the
// fingerprint distinguishes it, because the root never changed and the
// untrusted intermediate state is never observed.
func TestExportReappliesAfterEditAndRetrust(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"FOO": "old"}}`)

	enter, err := BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	setState(t, stateFromScript(t, enter))

	writeConfig(t, root, `{"env": {"FOO": "new"}}`)
	if err := Trust(ConfigPath(root)); err != nil {
		t.Fatal(err)
	}
	script, err := BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `export FOO="new"`) {
		t.Errorf("edited and re-trusted config did not reapply:\n%s", script)
	}
	if st := stateFromScript(t, script); st.Fingerprint == "" {
		t.Error("reapplied state has no fingerprint")
	}
}

// Config values are zsh double-quoted source text: $HOME etc. must reach the
// shell unexpanded and unescaped, while the automatic WORKSPACE_PATH is a
// real path and stays literal.
func TestExportConfigValuesExpandInShell(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"HOGE": "$HOME/fuga"}}`)

	script, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `export HOGE="$HOME/fuga"`) {
		t.Errorf("config value not emitted as shell-expandable source:\n%s", script)
	}
	if !strings.Contains(script, "export WORKSPACE_PATH='"+root+"'") {
		t.Errorf("automatic WORKSPACE_PATH lost its literal quoting:\n%s", script)
	}
}

func TestFindDirenvFile(t *testing.T) {
	base := t.TempDir()
	child := filepath.Join(base, "ws", "repo")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	envrc := filepath.Join(base, ".envrc")
	if err := os.WriteFile(envrc, []byte("export A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := findDirenvFile(child); got != envrc {
		t.Errorf("findDirenvFile = %q, want %q", got, envrc)
	}
	if got := findDirenvFile(t.TempDir()); got != "" {
		t.Errorf("findDirenvFile without .envrc = %q, want empty", got)
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
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "typeset -g "+stateShellVar+"=") {
		t.Errorf("state is not committed last: %q", last)
	}
}

// Regression guard: state must never be re-exported. An exported
// __SALLYPORT_STATE would be inherited by every child process the
// workspace starts, defeating the isolation stateShellVar exists for.
func TestExportNeverExportsState(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/1password/agent.sock"}}`)

	enterScript, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enterScript, "export "+stateEnvKey) {
		t.Errorf("state was exported on enter:\n%s", enterScript)
	}

	st := stateFromScript(t, enterScript)
	setState(t, st)
	leaveScript, err := BuildExportScript(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(leaveScript, "export "+stateEnvKey) {
		t.Errorf("state was exported on leave:\n%s", leaveScript)
	}
}

// Regression guard: leaving a workspace must clear the state global by
// assignment, never `unset`. Under `setopt nounset` a later "${__sallyport_state}"
// reference to an unset global aborts the hook with `parameter not set`, which
// stops it permanently.
func TestExportLeaveClearsStateWithoutUnset(t *testing.T) {
	orig := "/original/agent.sock"
	setState(t, state{Root: "/somewhere/demo", Saved: map[string]*string{"SSH_AUTH_SOCK": &orig}})

	script, err := BuildExportScript(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "unset "+stateShellVar) {
		t.Errorf("leave unsets the state global; nounset would break the hook:\n%s", script)
	}
	if !strings.Contains(script, "typeset -g "+stateShellVar+"=''") {
		t.Errorf("leave does not clear the state global by assignment:\n%s", script)
	}
}

// Regression guard: the shim must read the state global with a default so
// `setopt nounset` cannot abort the hook, and must never reference it bare.
func TestZshHookStateReferenceIsNounsetSafe(t *testing.T) {
	script, err := ZshHook()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, `"$`+stateShellVar+`"`) {
		t.Errorf("shim references the state global without a nounset default:\n%s", script)
	}
	if !strings.Contains(script, `"${`+stateShellVar+`-}"`) {
		t.Errorf("shim does not guard the state reference against nounset:\n%s", script)
	}
}

// Regression guard: masking SIGINT must be confined with localtraps so a
// user-defined INT trap is restored on return, not clobbered. The old
// `trap - SIGINT` reset it to the default.
func TestZshHookPreservesUserIntTrap(t *testing.T) {
	script, err := ZshHook()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "localtraps") {
		t.Errorf("shim does not confine trap changes with localtraps:\n%s", script)
	}
	if strings.Contains(script, "trap - SIGINT") {
		t.Errorf("shim still resets SIGINT to default, clobbering user traps:\n%s", script)
	}
}

// Drive the real shim under zsh to prove the two shell-level fixes: a
// user-defined INT trap survives a hook run (localtraps), and running the hook
// under `setopt nounset` after the state global was cleared does not abort.
func TestZshHookRealZshBehavior(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}

	shim, err := ZshHook()
	if err != nil {
		t.Fatal(err)
	}
	// Replace the eval line with a no-op: this test exercises the shell
	// mechanics (trap/nounset), not the binary, which is not built here.
	lines := strings.Split(shim, "\n")
	for i, l := range lines {
		if strings.Contains(l, "eval \"$(") {
			lines[i] = "  :"
		}
	}
	shim = strings.Join(lines, "\n")

	script := shim + `
trap 'print USERTRAP' INT
_sallyport_hook
# zsh's bare ` + "`trap`" + ` lists set traps as ` + "`trap -- 'cmd' SIG`" + `; call it
# directly, not in $(...), which runs in a subshell that resets traps.
print "=== after-trap ==="
trap

setopt nounset
typeset -g ` + stateShellVar + `=''
val="${` + stateShellVar + `-}"
_sallyport_hook
print "nounset-ok"
`
	out, err := exec.Command(zsh, "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("zsh run failed: %v\n%s", err, out)
	}
	got := string(out)
	// The user INT trap must still be registered after the hook returns; the
	// listing carries its command body only if it survived.
	if !strings.Contains(got, "trap -- 'print USERTRAP' INT") {
		t.Errorf("user INT trap was clobbered by the hook:\n%s", got)
	}
	// The hook must complete under nounset with an empty state global.
	if !strings.Contains(got, "nounset-ok") {
		t.Errorf("hook aborted under nounset:\n%s", got)
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
