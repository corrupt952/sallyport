package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// reentryKey makes the test binary run as sallyport instead of running tests,
// so the checks below exercise the real main: the subcommand registrations, the
// top-level flag parsing, the usage the Commander renders, and the line that
// turns an ExitStatus into the process's exit code. None of that is reachable
// from a test that calls a command's Execute directly, because
// subcommands.DefaultCommander is built in init() and captures os.Stdout and
// os.Stderr as they were then. This is the shape cmd/go, cmd/vet and cmd/nm
// use, and it needs no separate build.
const reentryKey = "SALLYPORT_TEST_REENTRY"

func TestMain(m *testing.M) {
	if os.Getenv(reentryKey) != "" {
		main()
		return
	}
	// t.TempDir creates the directory it returns with os.Mkdir(dir, 0o777), so
	// under a permissive umask the workspaces below take group and world write
	// bits and the path checks refuse them -- correctly, and for a reason no
	// test here is about. The other two packages fix it for the same reason.
	syscall.Umask(0o022)
	os.Exit(m.Run())
}

type result struct {
	stdout string
	stderr string
	code   int
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	dir, home := newHome(t)
	return runIn(t, dir, home, args...)
}

// newHome returns a working directory inside the home it also returns. The path
// checks stop at the home, so a working directory beside it rather than under
// it leaves the walk running to the filesystem root -- which a Nix builder owns
// as neither the build user nor root, and rightly refuses.
func newHome(t *testing.T) (dir, home string) {
	t.Helper()
	home = t.TempDir()
	dir = filepath.Join(home, "ws")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, home
}

// runIn starts this binary as sallyport in dir. stdout and stderr are captured
// separately: which stream a command writes to is the thing under test, since
// the hook evals whatever reaches stdout.
func runIn(t *testing.T, dir, home string, args ...string) result {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = append(os.Environ(), reentryKey+"=1", "HOME="+home, "XDG_DATA_HOME="+home+"/data")
	cmd.Dir = dir
	cmd.WaitDelay = 5 * time.Second

	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("sallyport %v never finished", args)
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("sallyport %v: %v", args, err)
	}
	return result{stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()}
}

func writeWorkspace(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".sallyport.jsonc"), []byte(`{"env": {"OP_ACCOUNT": "x"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func trustedWorkspace(t *testing.T) (dir, home string) {
	t.Helper()
	dir, home = newHome(t)
	writeWorkspace(t, dir)
	if res := runIn(t, dir, home, "trust"); res.code != 0 {
		t.Fatalf("trust exited %d: %s", res.code, res.stderr)
	}
	return dir, home
}

// D01: the ExitStatus each command returns has to become the process's exit
// code. Replacing the conversion with a constant zero leaves every in-process
// test green, and a shell function that checks `sallyport trust` would believe
// a refusal succeeded.
func TestExitStatusReachesTheProcess(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"version succeeds", []string{"version"}, 0},
		{"trust without a config fails", []string{"trust"}, 1},
		{"untrust without a config fails", []string{"untrust"}, 1},
		{"a bad shell name is a usage error", []string{"hook", "bash"}, 2},
		{"an unknown subcommand is a usage error", []string{"nonesuch"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, tc.args...).code; got != tc.want {
				t.Errorf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}

// D02: a command that is not registered cannot be reached, and the in-process
// tests call Execute directly, so dropping a Register line breaks nothing they
// can see.
func TestEverySubcommandIsRegistered(t *testing.T) {
	// One process for the whole list rather than one per name: the answer is a
	// list, and starting the binary nine times to read nine lines of it costs
	// most of this file's runtime under -race.
	listed := run(t, "commands")
	if listed.code != 0 {
		t.Fatalf("commands exited %d: %s", listed.code, listed.stderr)
	}
	have := map[string]bool{}
	for _, name := range strings.Fields(listed.stdout) {
		have[name] = true
	}
	for _, name := range []string{"create", "hook", "export", "trust", "untrust", "prune", "version", "help", "commands"} {
		if !have[name] {
			t.Errorf("%q is not registered; got %v", name, listed.stdout)
		}
	}
	// The other direction, so the check above cannot pass by never looking.
	if res := run(t, "help", "nonesuch"); res.code == 0 {
		t.Errorf("an unknown subcommand reported success: %+v", res)
	}
}

// C61/C62/D25/E01: `eval "$(sallyport hook zsh)"` is how sallyport is
// installed. The shim has to arrive on stdout, whole, with nothing on stderr
// for the shell to swallow into the eval.
func TestHookWritesTheShimToStdoutOnly(t *testing.T) {
	res := run(t, "hook", "zsh")
	if res.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if res.stderr != "" {
		t.Errorf("hook wrote to stderr, which the eval would not see: %q", res.stderr)
	}
	for _, want := range []string{"_sallyport_hook", "chpwd_functions", "precmd_functions", "export"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("shim is missing %q:\n%s", want, res.stdout)
		}
	}
}

// C51/C52: the export script goes to stdout for the same reason, and a warning
// on stdout would be eval'd as a command. Run from a workspace, since a
// directory with no config has nothing to say and would pass either way.
func TestExportWritesTheScriptToStdoutAndWarningsToStderr(t *testing.T) {
	dir, home := trustedWorkspace(t)
	res := runIn(t, dir, home, "export", "zsh")
	if res.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "OP_ACCOUNT") {
		t.Errorf("the script did not reach stdout, where the hook evals it:\nstdout: %q\nstderr: %q", res.stdout, res.stderr)
	}
	if strings.Contains(res.stderr, "OP_ACCOUNT") {
		t.Errorf("the script reached stderr, which the eval does not see: %q", res.stderr)
	}

	// An untrusted workspace warns, and that warning must not be eval'd.
	untrusted := filepath.Join(home, "other")
	if err := os.Mkdir(untrusted, 0o755); err != nil {
		t.Fatal(err)
	}
	writeWorkspace(t, untrusted)
	res = runIn(t, untrusted, home, "export", "zsh")
	if !strings.Contains(res.stderr, "sallyport:") {
		t.Errorf("no warning on stderr for an untrusted workspace: %q", res.stderr)
	}
	if strings.Contains(res.stdout, "sallyport:") {
		t.Errorf("a warning reached stdout, where the shell would eval it:\n%s", res.stdout)
	}
}

// C54/C55: the installed shim passes -quiet on every prompt. A renamed flag
// turns each prompt into an error, and an ignored one puts a warning on every
// one of them.
func TestQuietIsAcceptedAndObeyed(t *testing.T) {
	dir, home := newHome(t)
	writeWorkspace(t, dir)

	res := runIn(t, dir, home, "export", "-quiet", "zsh")
	if strings.Contains(res.stderr, "flag provided but not defined") {
		t.Fatalf("the flag the shim passes is gone: %s", res.stderr)
	}
	if res.code != 0 {
		t.Fatalf("export -quiet exited %d, which every prompt would report: %s", res.code, res.stderr)
	}
	if strings.Contains(res.stderr, "sallyport:") {
		t.Errorf("-quiet was ignored, so every prompt carries this: %q", res.stderr)
	}
	// The same workspace without -quiet does warn, so the check above cannot
	// pass by there being nothing to suppress.
	if loud := runIn(t, dir, home, "export", "zsh"); !strings.Contains(loud.stderr, "sallyport:") {
		t.Errorf("nothing to suppress, so -quiet proves nothing: %q", loud.stderr)
	}
}

// E03/E04/C44/C38: the two commands that report what they did, rather than
// answering a question. Nothing held their success paths, so "always fails" and
// "succeeds with a usage error" both passed.
func TestCreateAndPruneSucceedAndSayWhatHappened(t *testing.T) {
	dir, home := newHome(t)
	created := runIn(t, dir, home, "create")
	if created.code != 0 {
		t.Fatalf("create exited %d: %s", created.code, created.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".sallyport.jsonc")); err != nil {
		t.Fatalf("create reported success without writing a config: %v", err)
	}
	if created.stdout == "" && created.stderr == "" {
		t.Error("create said nothing about what it wrote")
	}

	pruned := runIn(t, dir, home, "prune")
	if pruned.code != 0 {
		t.Fatalf("prune exited %d: %s", pruned.code, pruned.stderr)
	}
	if pruned.stdout == "" && pruned.stderr == "" {
		t.Error("prune said nothing about what it removed")
	}
}

// The usage a user sees has to stay off stdout: for export and hook that stream
// is eval'd, so usage text arriving there is executed.
func TestUsageGoesToStderr(t *testing.T) {
	res := run(t, "hook", "bash")
	if res.stderr == "" {
		t.Error("a usage error printed nothing to stderr")
	}
	if strings.Contains(res.stdout, "Usage") {
		t.Errorf("usage reached stdout, where the shell would eval it:\n%s", res.stdout)
	}
}

// The shim is only correct if a real shell accepts it. zoxide checks its own
// init output the same way; the CI installs zsh for the tests that already do
// this in the workspace package.
func TestTheShimLoadsInARealZsh(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, zsh, "-f")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), reentryKey+"=1", "HOME="+t.TempDir())
	cmd.Stdin = strings.NewReader(`eval "$(` + self + ` hook zsh)"` + "\nprint READY\n")
	cmd.WaitDelay = 5 * time.Second

	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("zsh never finished:\n%s", out)
	}
	if err != nil {
		t.Fatalf("zsh refused the shim: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "READY") {
		t.Errorf("the shell did not get past the shim:\n%s", out)
	}
}
