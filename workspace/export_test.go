package workspace

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	return exportUntrustedWorkspaceDirNamed(t, "demo", config)
}

// exportUntrustedWorkspaceDirNamed is newUntrustedWorkspaceDir with a
// caller-chosen directory name, so the workspace path itself can carry shell
// metacharacters.
func exportUntrustedWorkspaceDirNamed(t *testing.T, name, config string) string {
	t.Helper()
	// Isolate the trust store, but only once per test: rotating it on every
	// call would drop grants of workspaces created earlier in the same test.
	if cur := os.Getenv("XDG_DATA_HOME"); cur == "" || !strings.HasPrefix(cur, os.TempDir()) {
		t.Setenv("XDG_DATA_HOME", t.TempDir())
	}
	root := filepath.Join(t.TempDir(), name)
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

func mustBuild(t *testing.T, pwd string, quiet bool) string {
	t.Helper()
	res, err := BuildExportScript(pwd, quiet)
	if err != nil {
		t.Fatal(err)
	}
	return res.Script
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// forgeGrant writes a trust record for root's config bytes directly, bypassing
// Trust's parse check, as an older version with different parse rules would.
func forgeGrant(t *testing.T, root string) {
	t.Helper()
	abs, err := filepath.Abs(ConfigPath(root))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	store, err := trustDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, fingerprintBytes(abs, content)), []byte(abs+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExportEnterSavesOriginals(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	t.Setenv("SSH_AUTH_SOCK", "/original/agent.sock")
	t.Setenv("WORKSPACE_PATH", "placeholder")
	_ = os.Unsetenv("WORKSPACE_PATH")
	root := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/1password/agent.sock"}}`)

	script := mustBuild(t, root, false)
	for _, want := range []string{
		"export WORKSPACE_PATH='" + root + "'",
		// Strict mode is the default, so values are single-quoted.
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
	script := mustBuild(t, filepath.Join(root, "repo", "sub"), false)
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

	script := mustBuild(t, t.TempDir(), false)
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

// A variable that existed but was empty before the workspace must come back as
// an empty variable, not as an unset one: `${VAR-default}` and conditionals on
// `${VAR+set}` tell the two apart.
func TestExportRestoresEmptyOriginalAsEmpty(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	t.Setenv("OP_ACCOUNT", "")
	root := newWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "acct.example.com"}}`)

	st := stateFromScript(t, mustBuild(t, root, false))
	if got, hit := st.Saved["OP_ACCOUNT"]; !hit || got == nil || *got != "" {
		t.Fatalf("empty original not recorded as a value: %v", st.Saved)
	}

	setState(t, st)
	leave := mustBuild(t, t.TempDir(), false)
	if !strings.Contains(leave, "export OP_ACCOUNT=''") {
		t.Errorf("empty original not restored as an empty variable:\n%s", leave)
	}
	if strings.Contains(leave, "unset OP_ACCOUNT") {
		t.Errorf("empty original restored as unset:\n%s", leave)
	}
}

func TestExportSwitchKeepsPreWorkspaceOriginals(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	t.Setenv("SSH_AUTH_SOCK", "/original/agent.sock")
	rootA := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/a/agent.sock"}}`)
	rootB := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/b/agent.sock"}}`)

	enterA := mustBuild(t, rootA, false)
	stA := stateFromScript(t, enterA)

	// Simulate the shell having applied workspace a.
	setState(t, stA)
	t.Setenv("SSH_AUTH_SOCK", "/a/agent.sock")
	t.Setenv("WORKSPACE_PATH", rootA)

	enterB := mustBuild(t, rootB, false)
	if !strings.Contains(enterB, "export SSH_AUTH_SOCK='/b/agent.sock'") {
		t.Errorf("switch does not apply workspace b:\n%s", enterB)
	}
	stB := stateFromScript(t, enterB)
	if got := stB.Saved["SSH_AUTH_SOCK"]; got == nil || *got != "/original/agent.sock" {
		t.Errorf("pre-workspace original lost on switch: %v", got)
	}
}

// The switch counterpart of TestExportRestoresEmptyOriginalAsEmpty: a variable
// that did not exist before workspace a must still be recorded as absent by the
// state workspace b writes. Otherwise b records a's value as the original and
// leaving b leaks it into the bare shell for good.
func TestExportSwitchKeepsUnsetOriginal(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	_ = os.Unsetenv("OP_ACCOUNT")
	rootA := newWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "from-a"}}`)
	rootB := newWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "from-b"}}`)

	// Simulate the shell having applied workspace a.
	setState(t, stateFromScript(t, mustBuild(t, rootA, false)))
	t.Setenv("OP_ACCOUNT", "from-a")

	stB := stateFromScript(t, mustBuild(t, rootB, false))
	if orig, hit := stB.Saved["OP_ACCOUNT"]; !hit || orig != nil {
		t.Fatalf("the switch recorded a's value as the pre-workspace original: %v", stB.Saved)
	}

	setState(t, stB)
	leave := mustBuild(t, t.TempDir(), false)
	if !strings.Contains(leave, "unset OP_ACCOUNT") {
		t.Errorf("leaving b keeps a variable that never existed:\n%s", leave)
	}
}

func TestExportIgnoresBrokenConfig(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newUntrustedWorkspaceDir(t, `{"env": {"$(whoami)": "x"}}`)
	// Trust refuses unparseable configs, so forge the grant directly.
	forgeGrant(t, root)

	script := mustBuild(t, root, false)
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

	script := mustBuild(t, root, false)
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

	script := mustBuild(t, root, false)
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
	script := mustBuild(t, root, true)
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

	script := mustBuild(t, root, true)
	if strings.Contains(script, "late.example.com") {
		t.Fatalf("applied before trust:\n%s", script)
	}

	if err := Trust(ConfigPath(root)); err != nil {
		t.Fatal(err)
	}
	// Same pwd, no cd: the very next evaluation must apply the workspace.
	script = mustBuild(t, root, true)
	if !strings.Contains(script, "export OP_ACCOUNT='late.example.com'") {
		t.Errorf("trust did not take effect without a cd:\n%s", script)
	}
}

// The shim must not invoke the hook while .zshrc is still being sourced: later
// export lines would clobber applied values and be recorded as the ones to
// restore.
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

// The state must stay non-exported and reach the binary only as a one-shot,
// invocation-scoped env var: an exported state would be inherited by every
// child process the workspace starts.
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

	script := mustBuild(t, link, false)
	if !strings.Contains(script, "export OP_ACCOUNT='alias.example.com'") {
		t.Fatalf("symlinked entry did not apply:\n%s", script)
	}
	st := stateFromScript(t, script)
	if st.Root != root {
		t.Errorf("state root = %q, want canonical %q", st.Root, root)
	}

	// Moving to the canonical path afterwards must be a no-op.
	setState(t, st)
	script = mustBuild(t, root, false)
	if script != "" {
		t.Errorf("alias switch caused churn:\n%s", script)
	}
}

// A config deployed as a symlink (Nix/home-manager) must be discovered,
// trusted, and applied end-to-end exactly like a regular-file config.
func TestExportAppliesSymlinkedConfig(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	base := t.TempDir()
	root := filepath.Join(base, "ws")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// State roots are canonical (macOS symlinks TMPDIR).
	if c, err := filepath.EvalSymlinks(root); err == nil {
		root = c
	}
	target := filepath.Join(base, "store", "config")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"env": {"OP_ACCOUNT": "sym.example.com"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, ConfigPath(root)); err != nil {
		t.Fatal(err)
	}
	if err := Trust(ConfigPath(root)); err != nil {
		t.Fatal(err)
	}

	script := mustBuild(t, root, false)
	if !strings.Contains(script, "export OP_ACCOUNT='sym.example.com'") {
		t.Errorf("symlinked config was not applied:\n%s", script)
	}
	if st := stateFromScript(t, script); st.Root != root {
		t.Errorf("state root = %q, want %q", st.Root, root)
	}
}

// An edit that gets re-trusted between two prompts must reapply: only the
// fingerprint distinguishes it, since the root never changed.
func TestExportReappliesAfterEditAndRetrust(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"FOO": "old"}}`)

	enter := mustBuild(t, root, true)
	setState(t, stateFromScript(t, enter))

	writeConfig(t, root, `{"env": {"FOO": "new"}}`)
	if err := Trust(ConfigPath(root)); err != nil {
		t.Fatal(err)
	}
	script := mustBuild(t, root, true)
	if !strings.Contains(script, "export FOO='new'") {
		t.Errorf("edited and re-trusted config did not reapply:\n%s", script)
	}
	if st := stateFromScript(t, script); st.Fingerprint == "" {
		t.Error("reapplied state has no fingerprint")
	}
}

// In expand mode config values are zsh double-quoted source text: $HOME must
// reach the shell unexpanded, while WORKSPACE_PATH stays literal.
func TestExportConfigValuesExpandInShell(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"expand": true, "env": {"HOGE": "$HOME/fuga"}}`)

	script := mustBuild(t, root, false)
	if !strings.Contains(script, `export HOGE="$HOME/fuga"`) {
		t.Errorf("config value not emitted as shell-expandable source:\n%s", script)
	}
	if !strings.Contains(script, "export WORKSPACE_PATH='"+root+"'") {
		t.Errorf("automatic WORKSPACE_PATH lost its literal quoting:\n%s", script)
	}
}

// In strict mode (the default) a value containing $HOME must reach the shell
// literally: single-quoted, so zsh performs no expansion.
func TestExportStrictModeDoesNotExpandInZsh(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	t.Setenv(stateEnvKey, "")
	_ = os.Unsetenv("HOGE")
	root := newWorkspaceDir(t, `{"env": {"HOGE": "$HOME/fuga"}}`)

	enter := mustBuild(t, root, false)
	if !strings.Contains(enter, "export HOGE='$HOME/fuga'") {
		t.Fatalf("strict value not single-quoted:\n%s", enter)
	}
	out, err := exec.Command(zsh, "-c", "HOME=/sallyport-home\n"+enter+"\nprintf 'HOGE=%s\\n' \"$HOGE\"\n").CombinedOutput()
	if err != nil {
		t.Fatalf("zsh run failed: %v\n%s", err, out)
	}
	if got := string(out); !strings.Contains(got, "HOGE=$HOME/fuga") {
		t.Errorf("strict mode expanded the value in zsh:\n%s", got)
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
// mid-write, the next evaluation redoes the whole (idempotent) transition.
func TestExportCommitsStateLast(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/1password/agent.sock"}}`)

	script := mustBuild(t, root, false)
	lines := strings.Split(strings.TrimRight(script, "\n"), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "typeset -g "+stateShellVar+"=") {
		t.Errorf("state is not committed last: %q", last)
	}
}

// State must never be re-exported: an exported __SALLYPORT_STATE would be
// inherited by every child process the workspace starts.
func TestExportNeverExportsState(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/1password/agent.sock"}}`)

	enterScript := mustBuild(t, root, false)
	if strings.Contains(enterScript, "export "+stateEnvKey) {
		t.Errorf("state was exported on enter:\n%s", enterScript)
	}

	st := stateFromScript(t, enterScript)
	setState(t, st)
	leaveScript := mustBuild(t, t.TempDir(), false)
	if strings.Contains(leaveScript, "export "+stateEnvKey) {
		t.Errorf("state was exported on leave:\n%s", leaveScript)
	}
}

// Leaving a workspace must clear the state global by assignment, never `unset`:
// under `setopt nounset` a later reference to an unset global aborts the hook
// with `parameter not set`, which stops it permanently.
func TestExportLeaveClearsStateWithoutUnset(t *testing.T) {
	orig := "/original/agent.sock"
	setState(t, state{Root: "/somewhere/demo", Saved: map[string]*string{"SSH_AUTH_SOCK": &orig}})

	script := mustBuild(t, t.TempDir(), false)
	if strings.Contains(script, "unset "+stateShellVar) {
		t.Errorf("leave unsets the state global; nounset would break the hook:\n%s", script)
	}
	if !strings.Contains(script, "typeset -g "+stateShellVar+"=''") {
		t.Errorf("leave does not clear the state global by assignment:\n%s", script)
	}
}

// The shim must read the state global with a default so `setopt nounset` cannot
// abort the hook.
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

// exportMasksInterrupt reports whether the shim sets INT to the ignore handler,
// however it spells the empty handler and the signal name: what matters is that
// a mask is installed, not which of zsh's accepted forms it takes.
func exportMasksInterrupt(script string) bool {
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "trap ") || !strings.HasSuffix(line, "INT") {
			continue
		}
		if strings.Contains(line, `''`) || strings.Contains(line, `""`) {
			return true
		}
	}
	return false
}

// The property is the pair: the hook masks INT for its own duration, and the
// user's trap is what INT means again afterwards. A missing mask makes the
// preservation vacuous, escaping the mask leaks it past the return, and
// `trap - SIGINT` would drop the user's trap to the default. Kept cheap so it
// still runs where zsh is unavailable;
// TestZshHookRealZshMasksInterruptAndSucceeds is the behavioural judge.
func TestZshHookPreservesUserIntTrap(t *testing.T) {
	script, err := ZshHook()
	if err != nil {
		t.Fatal(err)
	}
	if !exportMasksInterrupt(script) {
		t.Errorf("shim never masks INT, so there is no trap to preserve:\n%s", script)
	}
	if !strings.Contains(script, "localtraps") {
		t.Errorf("shim does not confine trap changes with localtraps:\n%s", script)
	}
	if strings.Contains(script, "trap - SIGINT") {
		t.Errorf("shim still resets SIGINT to default, clobbering user traps:\n%s", script)
	}
}

// Drive the real shim under zsh: a user-defined INT trap survives a hook run,
// and the hook does not abort under `setopt nounset` with a cleared state.
func TestZshHookRealZshBehavior(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}

	shim, err := ZshHook()
	if err != nil {
		t.Fatal(err)
	}
	// This test exercises the shell mechanics, not the binary, which is not built
	// here.
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
	// The listing carries the trap's command body only if it survived.
	if !strings.Contains(got, "trap -- 'print USERTRAP' INT") {
		t.Errorf("user INT trap was clobbered by the hook:\n%s", got)
	}
	if !strings.Contains(got, "nounset-ok") {
		t.Errorf("hook aborted under nounset:\n%s", got)
	}
}

// hostileBinaryPaths are directory names an installed sallyport can plausibly
// sit under, each carrying a character the shell would act on if the shim did
// not quote the path: $ and ` expand, " and ' end a quoted string, ! is history
// expansion, ; and & are command separators, and a space merely has to survive.
var hostileBinaryPaths = []string{
	`a$b`,
	"c`d",
	`e f`,
	`p'q`,
	`r"s`,
	`t;touch OOPS;u`,
	`v!w&x`,
	"a$b`c d'e\"f;g",
}

// Kept cheap so it still runs where zsh is unavailable. It deliberately does not
// compare against zshQuote's output: that would pass just as happily for a
// wrapper putting bare single quotes around the path, which dies on the first
// apostrophe. Requiring the path to have been altered catches that while
// leaving a differently-but-correctly quoting implementation free.
func TestZshHookQuotesBinaryPath(t *testing.T) {
	// Contains both an apostrophe and a $, so every quoting scheme has to escape
	// something.
	const self = `/opt/o'brien/a$b/sallyport`
	script := zshHookFor(self)
	if strings.Contains(script, self) {
		t.Errorf("shim carries the binary path verbatim, so the shell rewrites it:\n%s", script)
	}
}

// The real judge: for every hostile path, plant a stand-in binary there, render
// the shim for that exact path, and let zsh run the hook. The assertion is
// purely behavioural — did zsh manage to exec the file — so any correct quoting
// scheme passes and any broken one fails. The stand-in is reached through the
// shim's own `eval "$( ... )"`, so this exercises the real nested quoting
// context rather than a hand-written approximation. Render the shim rather than
// patching a path into ZshHook's output: a substitution that matches nothing
// leaves the shim invoking the test binary, which re-runs the whole suite.
func TestZshHookRealZshRunsBinaryAtHostilePath(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}

	for _, name := range hostileBinaryPaths {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			// The stand-in only has to be executable and print something evalable.
			fake := filepath.Join(dir, "sallyport")
			if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf 'export SALLYPORT_PROBE=ok\\n'\n"), 0o755); err != nil {
				t.Fatal(err)
			}

			// Broken quoting can leave zsh waiting on a command substitution the
			// path opened; WaitDelay caps the wait on the output pipe afterwards,
			// so a regression reports instead of hanging the test binary.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, zsh, "-c", zshHookFor(fake)+`
# ${+functions[...]} is 0 when the shim failed to parse: a mangled path can
# break the enclosing function definition, not just the exec.
printf 'HOOKDEF=%s\n' "${+functions[_sallyport_hook]}"
_sallyport_hook
printf 'PROBE=%s\n' "${SALLYPORT_PROBE-<unset>}"
`)
			cmd.Dir = dir
			cmd.WaitDelay = 5 * time.Second
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("zsh never finished for a binary at %q:\n%s", dir, out)
			}
			if err != nil {
				t.Fatalf("zsh run failed: %v\n%s", err, out)
			}
			got := string(out)
			if !strings.Contains(got, "HOOKDEF=1") {
				t.Errorf("shim for a binary at %q did not even define the hook:\n%s", dir, got)
			}
			if !strings.Contains(got, "PROBE=ok") {
				t.Errorf("hook did not run the binary at %q:\n%s", dir, got)
			}
			// The `;touch OOPS;` case leaves this file behind if the path was run.
			if _, err := os.Stat(filepath.Join(dir, "OOPS")); err == nil {
				t.Errorf("the binary path was executed as a command for %q", dir)
			}
		})
	}
}

// The untrusted warning is silenced on quiet (per-prompt) calls unless the
// workspace being rolled back is the one currently applied.
func TestExportUntrustedWarningGating(t *testing.T) {
	root := newUntrustedWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "x"}}`)

	t.Setenv(stateEnvKey, "")
	res, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "is not trusted") {
		t.Errorf("expected untrusted warning when not quiet: %v", res.Warnings)
	}

	// Quiet, and the applied workspace is elsewhere: stay silent.
	setState(t, state{Root: "/somewhere/else"})
	res, err = BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if hasWarning(res.Warnings, "is not trusted") {
		t.Errorf("untrusted warning should be suppressed under quiet away from the applied root: %v", res.Warnings)
	}

	// Quiet, but this very workspace was applied (trust revoked in place):
	// force the warning, since the environment is being rolled back.
	setState(t, state{Root: root})
	res, err = BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "is not trusted") {
		t.Errorf("untrusted warning must be forced when the applied workspace was revoked: %v", res.Warnings)
	}
}

// An insecure trust store is treated like an untrusted workspace: nothing is
// applied and the warning follows the same gating.
func TestExportUnsafeTrustStoreWarningGating(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses ownership and permission checks")
	}
	root := newWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "x"}}`)
	// Make the store forgeable after the grant was recorded.
	store, err := trustDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store, 0o770); err != nil {
		t.Fatal(err)
	}

	t.Setenv(stateEnvKey, "")
	res, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "not secure") {
		t.Errorf("expected unsafe-store warning when not quiet: %v", res.Warnings)
	}
	if strings.Contains(res.Script, "OP_ACCOUNT='x'") {
		t.Errorf("workspace applied despite an insecure store:\n%s", res.Script)
	}

	// Quiet, and the applied workspace is elsewhere: stay silent.
	setState(t, state{Root: "/somewhere/else"})
	res, err = BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if hasWarning(res.Warnings, "not secure") {
		t.Errorf("unsafe-store warning should be suppressed under quiet away from the applied root: %v", res.Warnings)
	}

	// Quiet, but this very workspace is applied: force the warning, since the
	// environment is being rolled back.
	setState(t, state{Root: root, Saved: map[string]*string{"OP_ACCOUNT": nil}})
	res, err = BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "not secure") {
		t.Errorf("unsafe-store warning must be forced when the applied workspace can no longer be trusted: %v", res.Warnings)
	}
	// The rollback must reach the shell, not just the warning: a script that
	// leaves the state pointing at the root would keep the workspace applied and
	// repeat the warning on every prompt.
	for _, want := range []string{"unset OP_ACCOUNT", "typeset -g " + stateShellVar + "=''"} {
		if !strings.Contains(res.Script, want) {
			t.Errorf("rollback script missing %q:\n%s", want, res.Script)
		}
	}
}

func TestExportBrokenConfigWarningGating(t *testing.T) {
	root := newUntrustedWorkspaceDir(t, `{"env": {"$(whoami)": "x"}}`)
	forgeGrant(t, root)

	t.Setenv(stateEnvKey, "")
	res, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "ignoring broken") {
		t.Errorf("expected broken-config warning when not quiet: %v", res.Warnings)
	}

	res, err = BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if hasWarning(res.Warnings, "ignoring broken") {
		t.Errorf("broken-config warning should be suppressed under quiet: %v", res.Warnings)
	}
}

func TestExportDirenvCoexistenceWarningGating(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "x"}}`)
	if err := os.WriteFile(filepath.Join(root, ".envrc"), []byte("export A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "managed by direnv") {
		t.Errorf("expected direnv coexistence warning when not quiet: %v", res.Warnings)
	}

	res, err = BuildExportScript(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if hasWarning(res.Warnings, "managed by direnv") {
		t.Errorf("direnv warning should be suppressed under quiet: %v", res.Warnings)
	}
}

func TestExportCorruptStateWarns(t *testing.T) {
	t.Setenv(stateEnvKey, "!!!not-base64!!!")
	res, err := BuildExportScript(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "is corrupted") {
		t.Errorf("expected corrupt-state warning: %v", res.Warnings)
	}
}

// A state written by a different sallyport version must still have its recovered
// originals applied: the mismatch is best-effort, not a reset.
func TestExportSchemaMismatchWarnsButKeepsState(t *testing.T) {
	// Legacy blob: a previous workspace's saved original, no schema field.
	legacy := base64.StdEncoding.EncodeToString([]byte(
		`{"root":"/previous/demo","saved":{"SSH_AUTH_SOCK":"/original/agent.sock"}}`))

	t.Setenv(stateEnvKey, legacy)
	res, err := BuildExportScript(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "different sallyport version") {
		t.Errorf("expected schema-mismatch warning: %v", res.Warnings)
	}
	// Rolled back despite the mismatch, rather than discarded like a corrupt state.
	if !strings.Contains(res.Script, "export SSH_AUTH_SOCK='/original/agent.sock'") {
		t.Errorf("legacy state's originals were not applied:\n%s", res.Script)
	}

	t.Setenv(stateEnvKey, legacy)
	res, err = BuildExportScript(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	if hasWarning(res.Warnings, "different sallyport version") {
		t.Errorf("schema-mismatch warning should be suppressed under quiet: %v", res.Warnings)
	}
}

func TestDecodeState(t *testing.T) {
	// The empty string is "no state", the same value the hook writes on leave.
	if s, mismatch, err := decodeState(""); err != nil || mismatch || s.Root != "" {
		t.Errorf("empty string: state=%v mismatch=%v err=%v, want zero state, no mismatch, nil", s, mismatch, err)
	}
	enc, err := encodeState(state{Root: "/x", Fingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	// A state this binary just encoded carries the current schema.
	if s, mismatch, err := decodeState(enc); err != nil || mismatch || s.Root != "/x" || s.Fingerprint != "fp" {
		t.Errorf("roundtrip: state=%v mismatch=%v err=%v", s, mismatch, err)
	}
	if _, _, err := decodeState("@@@not-base64"); err == nil {
		t.Error("invalid base64 accepted, want error")
	}
	notJSON := base64.StdEncoding.EncodeToString([]byte("not json"))
	if _, _, err := decodeState(notJSON); err == nil {
		t.Error("valid base64 but invalid JSON accepted, want error")
	}
}

// The standard and URL-safe base64 alphabets differ in exactly two characters,
// so a payload of plain ASCII round-trips even when encode and decode disagree
// about which alphabet they speak. These values push the encoding onto those
// two characters, where a disagreement shows up as a state that fails to decode
// and takes the pre-workspace originals with it.
func TestDecodeStateRoundTripsAlphabetSpecificPayloads(t *testing.T) {
	values := []string{
		"~/.local/bin:/usr/bin",
		"/home/o~brien/bin",
		"~?~",
		"a?b~c?d~",
	}
	alphabetSpecific, padded := false, false
	for _, want := range values {
		orig := want
		enc, err := encodeState(state{Root: "/x", Saved: map[string]*string{"PATH": &orig}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(enc, "+/") {
			alphabetSpecific = true
		}
		if strings.HasSuffix(enc, "=") {
			padded = true
		}
		if len(enc)%4 != 0 {
			t.Errorf("encoding of %q is not padded to a multiple of four: %s", want, enc)
		}
		s, _, err := decodeState(enc)
		if err != nil {
			t.Fatalf("state carrying %q failed to round-trip: %v", want, err)
		}
		if got := s.Saved["PATH"]; got == nil || *got != want {
			t.Errorf("saved original lost: got %v, want %q", got, want)
		}
	}
	// Both guards fail for two reasons: the encoding changed, or the payloads
	// drifted off the property they were chosen for. Check the encoding first.
	if !alphabetSpecific {
		t.Error("no payload encoded to a + or /: either encodeState left the standard alphabet, or these payloads no longer reach the two characters the alphabets disagree on")
	}
	if !padded {
		t.Error("no payload encoded to a trailing =: either encodeState dropped padding, or no payload has a length that needs it")
	}
}

// This pins the state wire layout: changing the state struct changes the string
// and fails the test on purpose. Go's json ignores unknown fields and zero-fills
// missing ones, so ADDING an optional field is compatible; when you change the
// MEANING of an existing field you MUST also change its JSON field name, so old
// state reads as a (safe) missing field instead of being silently misread.
func TestStateSchemaString(t *testing.T) {
	const want = "fingerprint:string,root:string,saved:map[string]*string"
	if got := stateSchemaString(); got != want {
		t.Errorf("state schema changed:\n got %q\nwant %q\nRead this test's comment before updating want.", got, want)
	}
}

// A state written by a different layout must decode, be flagged as a mismatch,
// and still yield its recovered originals.
func TestDecodeStateSchemaMismatchKeepsData(t *testing.T) {
	legacy := base64.StdEncoding.EncodeToString([]byte(`{"root":"/x","saved":{"FOO":null}}`))
	s, mismatch, err := decodeState(legacy)
	if err != nil {
		t.Fatalf("legacy state failed to decode: %v", err)
	}
	if !mismatch {
		t.Error("missing schema not flagged as mismatch")
	}
	if s.Root != "/x" {
		t.Errorf("compatible field lost across schema mismatch: root=%q", s.Root)
	}
	if _, hit := s.Saved["FOO"]; !hit {
		t.Errorf("saved originals lost across schema mismatch: %v", s.Saved)
	}
}

// renderScript is pure, so it can be exercised directly.
func TestRenderScript(t *testing.T) {
	orig := "/old/sock"
	saved := map[string]*string{"KEEP": &orig, "GONE": nil}
	vars := []EnvVar{
		{Key: "APPLIED", Val: "$HOME/x"},
		{Key: "LIT", Val: "/real/path", Literal: true},
	}
	stateLine := "typeset -g " + stateShellVar + "='ENC'\n"
	script := renderScript(saved, vars, stateLine)

	for _, want := range []string{
		"export KEEP='/old/sock'",
		"unset GONE",
		`export APPLIED="$HOME/x"`,
		"export LIT='/real/path'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("rendered script missing %q:\n%s", want, script)
		}
	}
	if strings.Index(script, "KEEP") > strings.Index(script, "APPLIED") {
		t.Errorf("restores not emitted before applies:\n%s", script)
	}
	lines := strings.Split(strings.TrimRight(script, "\n"), "\n")
	if last := lines[len(lines)-1]; last != strings.TrimRight(stateLine, "\n") {
		t.Errorf("state line not last: %q", last)
	}
}

// exportReadZshWord reads a rendered word the way zsh does: a single-quoted
// span is literal (a backslash inside it escapes nothing), a double-quoted span
// honours backslash escapes but still expands $ and `, and outside quotes a
// backslash escapes the next byte. Anything else zsh would not read as one
// plain word — unquoted whitespace, a metacharacter, an unterminated quote —
// reports false, which is exactly what a broken quoting scheme produces.
func exportReadZshWord(word string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(word); i++ {
		switch c := word[i]; c {
		case '\'':
			end := strings.IndexByte(word[i+1:], '\'')
			if end < 0 {
				return "", false
			}
			b.WriteString(word[i+1 : i+1+end])
			i += end + 1
		case '"':
			for i++; ; i++ {
				if i >= len(word) {
					return "", false
				}
				if word[i] == '"' {
					break
				}
				if word[i] == '$' || word[i] == '`' {
					return "", false
				}
				if word[i] == '\\' {
					i++
					if i >= len(word) {
						return "", false
					}
				}
				b.WriteByte(word[i])
			}
		case '\\':
			i++
			if i >= len(word) {
				return "", false
			}
			b.WriteByte(word[i])
		default:
			if strings.IndexByte(" \t\n;&|<>()$`*?[]{}#~=", c) >= 0 {
				return "", false
			}
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// The safety net where zsh is unavailable, and the reason it does not compare
// against zshQuote's output: that would pass just as happily for a wrapper
// putting bare single quotes around the value, and would fail a
// differently-but-correctly quoting implementation. Reading the rendered word
// back instead judges the same property TestExportScriptEvalsInZshWithHostileLiterals
// judges, minus the shell.
func TestRenderScriptEscapesLiteralValues(t *testing.T) {
	for _, val := range []string{`it's $HOME`, `o'brien`, `plain`, `a"b`, `back\slash`, "two words"} {
		script := renderScript(nil, []EnvVar{{Key: "LIT", Val: val, Literal: true}}, "")
		word, found := strings.CutPrefix(strings.TrimSuffix(script, "\n"), "export LIT=")
		if !found {
			t.Fatalf("unexpected rendering for %q: %s", val, script)
		}
		got, ok := exportReadZshWord(word)
		if !ok || got != val {
			t.Errorf("renderScript emitted %s for %q; the shell reads it as %q (one word: %v)", word, val, got, ok)
		}
	}
}

// exportHostileLiteralValues are strict-mode values (and, through the workspace
// directory name, WORKSPACE_PATH) that a quoting scheme has to carry as text.
// The JSON source is given alongside the value it must produce, so a case is
// read as the config the user actually wrote.
var exportHostileLiteralValues = []struct {
	name string
	json string
	want string
}{
	{"apostrophe", `o'brien;touch OOPS;'`, `o'brien;touch OOPS;'`},
	{"double quote", `a\"b`, `a"b`},
	{"backslash", `back\\slash`, `back\slash`},
	{"substitution", `$(touch OOPS)`, `$(touch OOPS)`},
	{"backtick", "`touch OOPS`", "`touch OOPS`"},
	{"history bang", `!bang`, `!bang`},
	{"newline", `a\nb;touch OOPS`, "a\nb;touch OOPS"},
}

// The real judge for literal quoting: a workspace whose path and values both
// carry shell metacharacters. The assertion is behavioural — did zsh end up
// with the exact strings, and did it run nothing it was not asked to — so any
// correct quoting scheme passes and any broken one fails. WORKSPACE_PATH is
// always literal, so a directory named o'brien reaches that path with no config
// entry at all.
func TestExportScriptEvalsInZshWithHostileLiterals(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	for _, tc := range exportHostileLiteralValues {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(stateEnvKey, "")
			_ = os.Unsetenv("OP_ACCOUNT")
			_ = os.Unsetenv("WORKSPACE_PATH")
			root := exportUntrustedWorkspaceDirNamed(t, "o'brien", `{"env": {"OP_ACCOUNT": "`+tc.json+`"}}`)
			if err := Trust(ConfigPath(root)); err != nil {
				t.Fatal(err)
			}

			enter := mustBuild(t, root, false)
			setState(t, stateFromScript(t, enter))
			leave := mustBuild(t, t.TempDir(), false)

			// Broken quoting can leave zsh waiting on a quote or a command
			// substitution the value opened; WaitDelay caps the wait on the output
			// pipe afterwards, so a regression reports instead of hanging the test
			// binary (see TestZshHookRealZshRunsBinaryAtHostilePath).
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, zsh, "-c", enter+`
printf 'OP=%s\n' "$OP_ACCOUNT"
printf 'WS=%s\n' "$WORKSPACE_PATH"
`+leave+`
printf 'OP_after=%s\n' "${OP_ACCOUNT-<unset>}"
printf 'WS_after=%s\n' "${WORKSPACE_PATH-<unset>}"
`)
			cmd.Dir = root
			cmd.WaitDelay = 5 * time.Second
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("zsh never finished for %q:\n%s", tc.want, out)
			}
			if err != nil {
				t.Fatalf("zsh run failed: %v\n%s", err, out)
			}
			got := string(out)
			for _, want := range []string{
				"OP=" + tc.want,
				"WS=" + root,
				"OP_after=<unset>",
				"WS_after=<unset>",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("zsh output missing %q:\n%s", want, got)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "OOPS")); err == nil {
				t.Error("the value was executed as a command instead of being applied as text")
			}
		})
	}
}

// End-to-end: the generated enter/leave scripts must actually eval in zsh.
func TestExportScriptEvalsInZsh(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	t.Setenv(stateEnvKey, "")
	// The applied vars must have no prior value so leaving unsets them.
	_ = os.Unsetenv("OP_ACCOUNT")
	_ = os.Unsetenv("HOGE")
	_ = os.Unsetenv("WORKSPACE_PATH")
	root := newWorkspaceDir(t, `{"expand": true, "env": {"OP_ACCOUNT": "acct.example.com", "HOGE": "$HOME/fuga"}}`)

	enter := mustBuild(t, root, false)
	// Simulate the shell having applied the workspace, then leave it.
	setState(t, stateFromScript(t, enter))
	leave := mustBuild(t, t.TempDir(), false)

	script := "HOME=/sallyport-home\n" + enter + `
printf 'OP=%s\n' "$OP_ACCOUNT"
printf 'HOGE=%s\n' "$HOGE"
printf 'WS=%s\n' "$WORKSPACE_PATH"
` + leave + `
printf 'OP_after=%s\n' "${OP_ACCOUNT-<unset>}"
printf 'WS_after=%s\n' "${WORKSPACE_PATH-<unset>}"
`
	out, err := exec.Command(zsh, "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("zsh run failed: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{
		"OP=acct.example.com",       // literal config value applied
		"HOGE=/sallyport-home/fuga", // $HOME expanded by the shell
		"WS=" + root,                // automatic WORKSPACE_PATH
		"OP_after=<unset>",          // restored to its pre-workspace absence
		"WS_after=<unset>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("zsh output missing %q:\n%s", want, got)
		}
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

// exportForgedSavedKeys are saved keys no sallyport ever wrote: parseConfig's
// keyRe rejects them on the way in, so a state carrying one was forged. They
// land unquoted in `export KEY=` and `unset KEY`, which the shell evals, so
// each turns a restore into a command of the forger's choosing.
var exportForgedSavedKeys = []struct {
	name string
	key  string
}{
	{"command separator", "A; touch OOPS; echo"},
	{"command substitution", "A=$(touch OOPS); B"},
	{"newline", "A\ntouch OOPS\nB"},
	{"leading digit", "9A"},
	{"dash", "A-B"},
}

// A forged state must be discarded like a corrupt one: the restore keys are the
// only place a key reaches the shell without keyRe having seen it. Both branches
// are covered, because guarding one leaves the other live: a non-nil original
// renders `export KEY=`, a nil one `unset KEY`.
func TestExportDiscardsStateWithForgedSavedKeys(t *testing.T) {
	for _, tc := range exportForgedSavedKeys {
		for _, branch := range []string{"export", "unset"} {
			t.Run(tc.name+"/"+branch, func(t *testing.T) {
				var orig *string
				if branch == "export" {
					v := "x"
					orig = &v
				}
				setState(t, state{Root: "/somewhere/demo", Saved: map[string]*string{tc.key: orig}})

				res, err := BuildExportScript(t.TempDir(), false)
				if err != nil {
					t.Fatal(err)
				}
				if !hasWarning(res.Warnings, "is corrupted") {
					t.Errorf("forged state accepted without the corrupt-state warning: %v", res.Warnings)
				}
				for _, line := range strings.Split(res.Script, "\n") {
					if !strings.HasPrefix(line, "export ") && !strings.HasPrefix(line, "unset ") {
						continue
					}
					if strings.Contains(line, "OOPS") || strings.Contains(line, tc.key) {
						t.Errorf("forged key rendered into the script: %q\n%s", line, res.Script)
					}
				}
			})
		}
	}
}

// The real judge for the forged-key rejection: let zsh eval the script the hook
// would have eval'd and see whether the key ran as a command.
func TestExportForgedStateKeyDoesNotRunInZsh(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	dir := t.TempDir()
	setState(t, state{
		Root:  "/somewhere/demo",
		Saved: map[string]*string{"A; touch " + filepath.Join(dir, "OOPS") + "; echo": nil},
	})
	script := mustBuild(t, t.TempDir(), false)

	out := exportRunZsh(t, zsh, dir, script+"\nprint EVALED\n")
	if !strings.Contains(out, "EVALED") {
		t.Fatalf("the script did not eval at all:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "OOPS")); err == nil {
		t.Errorf("the forged saved key was executed as a command:\n%s", script)
	}
}

// Entering a workspace from a subdirectory must apply the workspace's own
// variables: WORKSPACE_PATH is what prompt integrations read, and building it
// from the cwd instead makes it drift with every cd below the root.
func TestExportFromSubdirectoryAppliesRootNotCwd(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"OP_ACCOUNT": "acct.example.com"}}`)
	sub := filepath.Join(root, "deep", "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	script := mustBuild(t, sub, false)
	if !strings.Contains(script, "export WORKSPACE_PATH='"+root+"'") {
		t.Errorf("WORKSPACE_PATH is not the workspace root when entering from %s:\n%s", sub, script)
	}
	if st := stateFromScript(t, script); st.Root != root {
		t.Errorf("state root = %q, want the workspace root %q", st.Root, root)
	}
}

// exportPlantStandin writes an executable stand-in for the sallyport binary and
// returns its path. The shim is rendered for the stand-in rather than having a
// path patched into ZshHook's output: a substitution that matches nothing
// leaves the shim invoking the test binary, which re-runs the whole suite.
func exportPlantStandin(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sallyport")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// exportRunZsh runs script under zsh in dir. A shim or a script that opens a
// quote or a command substitution it never closes leaves zsh waiting; WaitDelay
// caps the wait on the output pipe afterwards, so a regression reports instead
// of hanging the test binary.
func exportRunZsh(t *testing.T, zsh, dir, script string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, zsh, "-c", script)
	cmd.Dir = dir
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("zsh never finished:\n%s", out)
	}
	if err != nil {
		t.Fatalf("zsh run failed: %v\n%s", err, out)
	}
	return string(out)
}

// The shim must invoke the binary with an argument vector the export subcommand
// accepts, from both entry points. The real binary answers anything else with
// its usage on stderr and an empty stdout, which the hook evals to nothing: a
// sallyport that has silently stopped working. The stand-in enforces the same
// contract, so what is asserted is that outcome rather than a literal argument
// list.
func TestZshHookRealZshInvokesBinaryWithAcceptedArgs(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	standin := exportPlantStandin(t, `#!/bin/sh
for a in "$@"; do last="$a"; done
if [ "$1" != export ] || [ "$last" != zsh ]; then
  echo "usage: export [-quiet] zsh" >&2
  exit 2
fi
printf "export SALLYPORT_ARGS='%s'\n" "$*"
`)
	out := exportRunZsh(t, zsh, filepath.Dir(standin), zshHookFor(standin)+`
_sallyport_hook
printf 'CHPWD=%s\n' "${SALLYPORT_ARGS-<nothing evaled>}"
unset SALLYPORT_ARGS
_sallyport_hook_precmd
printf 'PRECMD=%s\n' "${SALLYPORT_ARGS-<nothing evaled>}"
`)
	// The per-prompt entry point has to reach the binary as the quiet variant, or
	// every empty Enter repeats the warnings.
	for _, want := range []string{"CHPWD=export zsh", "PRECMD=export -quiet zsh"} {
		if !strings.Contains(out, want) {
			t.Errorf("shim output missing %q:\n%s", want, out)
		}
	}
}

// Registration is the whole shim: chpwd for directory changes, and precmd so
// trust, untrust and config edits take effect on the next prompt without a cd.
// It goes in front of hooks already registered, so a workspace's values are in
// place before anything else in the array reads the environment, and it must
// survive .zshrc being sourced twice without stacking a second copy that runs
// the binary again on every prompt.
func TestZshHookRealZshRegistersOnceInFront(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	shim := zshHookFor(filepath.Join(t.TempDir(), "sallyport"))
	out := exportRunZsh(t, zsh, t.TempDir(), `
typeset -ag chpwd_functions precmd_functions
chpwd_functions=(user_chpwd)
precmd_functions=(user_precmd)
`+shim+shim+`
printf 'CHPWD=%s\n' "${(j: :)chpwd_functions}"
printf 'PRECMD=%s\n' "${(j: :)precmd_functions}"
`)
	for _, want := range []string{
		"CHPWD=_sallyport_hook user_chpwd",
		"PRECMD=_sallyport_hook_precmd user_precmd",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("shim registration is wrong, missing %q:\n%s", want, out)
		}
	}
}

// A Ctrl-C landing mid-hook must neither cut the eval short — which would leave
// the environment applied and the state global unwritten — nor reach a
// user-defined INT trap, and that trap must be back once the hook returns. The
// stand-in signals the shell while the hook waits on its output, then ends on a
// failing command: the hook still must not propagate a status, since zsh stops
// running the remaining chpwd hooks when one fails.
func TestZshHookRealZshMasksInterruptAndSucceeds(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	standin := exportPlantStandin(t, `#!/bin/sh
kill -INT "$SALLYPORT_TEST_ZSH_PID"
sleep 1
printf 'export SALLYPORT_PROBE=ok\n'
printf 'false\n'
`)
	out := exportRunZsh(t, zsh, filepath.Dir(standin), `
export SALLYPORT_TEST_ZSH_PID=$$
`+zshHookFor(standin)+`
trap 'INTFIRED=yes' INT
_sallyport_hook
printf 'STATUS=%s\n' "$?"
printf 'PROBE=%s\n' "${SALLYPORT_PROBE-<unset>}"
printf 'INTFIRED=%s\n' "${INTFIRED-no}"
# zsh's bare `+"`trap`"+` lists set traps as `+"`trap -- 'cmd' SIG`"+`, with the
# body re-rendered from the parsed code; call it directly, not in $(...), which
# runs in a subshell that resets traps.
trap
`)
	if !strings.Contains(out, "INTFIRED=no") {
		t.Errorf("SIGINT was not masked, so a Ctrl-C runs the user's trap mid-eval:\n%s", out)
	}
	if !strings.Contains(out, "PROBE=ok") {
		t.Errorf("SIGINT cut the eval short, leaving the transition half-applied:\n%s", out)
	}
	if !strings.Contains(out, "STATUS=0") {
		t.Errorf("hook propagated a failure; zsh would stop the remaining chpwd hooks:\n%s", out)
	}
	if !strings.Contains(out, "trap -- 'INTFIRED=yes") {
		t.Errorf("the mask outlived the hook instead of being confined to it:\n%s", out)
	}
}

// The schema stamp exists to catch state written by a binary with a different
// wire layout, so it has to be derived from that layout and long enough that
// two layouts do not stamp the same value: a collision is exactly the silent
// misread the stamp is there to prevent.
func TestStateSchemaDerivedFromLayout(t *testing.T) {
	sum := sha256.Sum256([]byte(stateSchemaString()))
	if full := hex.EncodeToString(sum[:]); !strings.HasPrefix(full, stateSchema) {
		t.Errorf("stateSchema %q does not hash the layout %q (whose digest is %s)", stateSchema, stateSchemaString(), full)
	}
	const minLen = 12
	if len(stateSchema) < minLen {
		t.Errorf("stateSchema is %d hex digits, want at least %d: %q", len(stateSchema), minLen, stateSchema)
	}
}
