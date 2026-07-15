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

// mustBuild runs BuildExportScript, fails on error, and returns the script.
// The warning-gating tests call BuildExportScript directly to inspect Warnings.
func mustBuild(t *testing.T, pwd string, quiet bool) string {
	t.Helper()
	res, err := BuildExportScript(pwd, quiet)
	if err != nil {
		t.Fatal(err)
	}
	return res.Script
}

// hasWarning reports whether any warning contains substr.
func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// forgeGrant writes a trust record for root's config bytes directly, bypassing
// Trust's parse check to simulate bytes approved by an older version with
// different parse rules.
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
	if err := os.MkdirAll(trustDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustDir(), fingerprintBytes(abs, content)), []byte(abs+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExportEnterSavesOriginals(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	t.Setenv("SSH_AUTH_SOCK", "/original/agent.sock")
	t.Setenv("WORKSPACE_PATH", "placeholder")
	os.Unsetenv("WORKSPACE_PATH")
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

func TestExportIgnoresBrokenConfig(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newUntrustedWorkspaceDir(t, `{"env": {"$(whoami)": "x"}}`)
	// Trust refuses unparseable configs, so forge the grant directly to
	// simulate bytes approved by an older version with different parse rules.
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

// An edit that gets re-trusted between two prompts must reapply: only the
// fingerprint distinguishes it, because the root never changed and the
// untrusted intermediate state is never observed.
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

// In expand mode config values are zsh double-quoted source text: $HOME etc.
// must reach the shell unexpanded and unescaped, while the automatic
// WORKSPACE_PATH is a real path and stays literal.
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
	os.Unsetenv("HOGE")
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
// mid-write, the shell evals a script whose state was never committed, and
// the next evaluation simply redoes the whole (idempotent) transition.
func TestExportCommitsStateLast(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"SSH_AUTH_SOCK": "/1password/agent.sock"}}`)

	script := mustBuild(t, root, false)
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

// Regression guard: leaving a workspace must clear the state global by
// assignment, never `unset`. Under `setopt nounset` a later "${__sallyport_state}"
// reference to an unset global aborts the hook with `parameter not set`, which
// stops it permanently.
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

// The untrusted warning is silenced on quiet (per-prompt) calls unless the
// workspace being rolled back is the one currently applied, in which case a
// silent rollback would confuse the user.
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
	// A value that is not valid base64 cannot be decoded.
	t.Setenv(stateEnvKey, "!!!not-base64!!!")
	res, err := BuildExportScript(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "is corrupted") {
		t.Errorf("expected corrupt-state warning: %v", res.Warnings)
	}
}

// A state written by a different sallyport version (here: no schema field) must
// warn on a non-quiet call, be suppressed on quiet, and still have its
// recovered originals applied — the mismatch is best-effort, not a reset.
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
	// Best-effort: the recovered original is still rolled back despite the
	// mismatch, rather than discarded like a corrupt state.
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
	// A state this binary just encoded carries the current schema, so it must
	// round-trip without a mismatch.
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

// stateSchemaString pins the state wire layout. If you change the state struct
// (add, remove, rename, or retype a field) this string changes and the test
// fails on purpose — decide whether the change is wire-compatible before
// updating `want`. Go's json ignores unknown fields and zero-fills missing
// ones, so ADDING an optional field is compatible; but when you change the
// MEANING of an existing field you MUST also change its JSON field name, so old
// state reads as a (safe) missing field instead of being silently misread.
func TestStateSchemaString(t *testing.T) {
	const want = "fingerprint:string,root:string,saved:map[string]*string"
	if got := stateSchemaString(); got != want {
		t.Errorf("state schema changed:\n got %q\nwant %q\nRead this test's comment before updating want.", got, want)
	}
}

// A state written by a different layout (here: no schema field, as older
// sallyport wrote) must decode, be flagged as a mismatch, and still yield its
// recovered originals — Go zero-fills the missing schema and keeps the rest.
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

// renderScript is pure, so it can be exercised directly: restores precede
// applies, literals are single-quoted while config values stay verbatim
// double-quoted source, and the state line is always last.
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

// End-to-end: the generated enter/leave scripts must actually eval in zsh,
// applying literal values, expanding config values, and restoring on leave.
func TestExportScriptEvalsInZsh(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	t.Setenv(stateEnvKey, "")
	// The applied vars must have no prior value so leaving unsets them.
	os.Unsetenv("OP_ACCOUNT")
	os.Unsetenv("HOGE")
	os.Unsetenv("WORKSPACE_PATH")
	// expand mode so the shell expands $HOME in the value below.
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
