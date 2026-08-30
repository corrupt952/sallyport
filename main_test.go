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

// runIn captures stdout and stderr separately because which stream a command
// writes to is the thing under test: the hook evals whatever reaches stdout.
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
	cmd.Env = append(cleanEnv(), reentryKey+"=1", "HOME="+home, "XDG_DATA_HOME="+filepath.Join(home, "data"))
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

// cleanEnv is the environment minus the two variables sallyport reads for
// itself. Inherited from whoever ran the tests, a stale state blob or an opt-out
// left over from debugging changes what the child does; testenv.CleanCmdEnv
// drops GODEBUG and GOTRACEBACK from GOROOT's exec tests for the same reason.
func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "__SALLYPORT_STATE=") || strings.HasPrefix(kv, "SALLYPORT_NO_PATH_CHECK=") {
			continue
		}
		env = append(env, kv)
	}
	return env
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

// The ExitStatus each command returns has to become the process's exit code.
// Replacing the conversion with a constant zero leaves every in-process test
// green, and a shell function checking `sallyport trust` would take a refusal
// for a success.
func TestExitStatusReachesTheProcess(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"version succeeds", []string{"version"}, 0},
		{"trust without a config fails", []string{"trust"}, 1},
		{"untrust without a config fails", []string{"untrust"}, 1},
		{"a bad shell name is a usage error", []string{"hook", "fish"}, 2},
		{"an unknown subcommand is a usage error", []string{"nonesuch"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := run(t, tc.args...).code; got != tc.want {
				t.Errorf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}

// A command that is not registered cannot be reached, and the in-process
// tests call Execute directly, so dropping a Register line breaks nothing they
// can see.
func TestEverySubcommandIsRegistered(t *testing.T) {
	t.Parallel()
	// One process for the whole list: starting the binary once per name is most
	// of this file's runtime under -race.
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
	// A name nobody registered has to be refused, or "registered" would mean
	// nothing.
	if res := run(t, "help", "nonesuch"); res.code == 0 {
		t.Errorf("an unknown subcommand reported success: %+v", res)
	}
}

// `eval "$(sallyport hook zsh)"` is how sallyport is installed, so the shim has
// to arrive on stdout, whole, with nothing on stderr for the eval to swallow.
func TestHookWritesTheShimToStdoutOnly(t *testing.T) {
	t.Parallel()
	for shell, markers := range map[string][]string{
		"zsh":  {"_sallyport_hook", "chpwd_functions", "precmd_functions", "export"},
		"bash": {"_sallyport_hook", "PROMPT_COMMAND", "export"},
	} {
		t.Run(shell, func(t *testing.T) {
			t.Parallel()
			res := run(t, "hook", shell)
			if res.code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %s)", res.code, res.stderr)
			}
			if res.stderr != "" {
				t.Errorf("hook wrote to stderr, which the eval would not see: %q", res.stderr)
			}
			for _, want := range markers {
				if !strings.Contains(res.stdout, want) {
					t.Errorf("shim is missing %q:\n%s", want, res.stdout)
				}
			}
		})
	}
}

// The export script goes to stdout for the same reason, and a warning there
// would be eval'd as a command. Run from a workspace, since a directory with no
// config has nothing to say and would pass either way.
func TestExportWritesTheScriptToStdoutAndWarningsToStderr(t *testing.T) {
	t.Parallel()
	dir, home := trustedWorkspace(t)
	for _, shell := range []string{"zsh", "bash"} {
		res := runIn(t, dir, home, "export", shell)
		if res.code != 0 {
			t.Fatalf("%s: exit code = %d, want 0 (stderr: %s)", shell, res.code, res.stderr)
		}
		if !strings.Contains(res.stdout, "OP_ACCOUNT") {
			t.Errorf("%s: the script did not reach stdout, where the hook evals it:\nstdout: %q\nstderr: %q", shell, res.stdout, res.stderr)
		}
		if strings.Contains(res.stderr, "OP_ACCOUNT") {
			t.Errorf("%s: the script reached stderr, which the eval does not see: %q", shell, res.stderr)
		}
	}

	// An untrusted workspace warns, and that warning must not be eval'd.
	untrusted := filepath.Join(home, "other")
	if err := os.Mkdir(untrusted, 0o755); err != nil {
		t.Fatal(err)
	}
	writeWorkspace(t, untrusted)
	res := runIn(t, untrusted, home, "export", "bash")
	if !strings.Contains(res.stderr, "sallyport:") {
		t.Errorf("no warning on stderr for an untrusted workspace: %q", res.stderr)
	}
	if strings.Contains(res.stdout, "sallyport:") {
		t.Errorf("a warning reached stdout, where the shell would eval it:\n%s", res.stdout)
	}
}

// The installed shim passes -quiet on every prompt. A renamed flag turns each
// prompt into an error, and an ignored one puts a warning on every one.
func TestQuietIsAcceptedAndObeyed(t *testing.T) {
	t.Parallel()
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

// The two commands that report what they did rather than answering a question.
// Nothing held their success paths, so "always fails" and "succeeds with a
// usage error" both passed.
func TestCreateAndPruneSucceedAndSayWhatHappened(t *testing.T) {
	t.Parallel()
	dir, home := newHome(t)
	created := runIn(t, dir, home, "create")
	if created.code != 0 {
		t.Fatalf("create exited %d: %s", created.code, created.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".sallyport.jsonc")); err != nil {
		t.Fatalf("create reported success without writing a config: %v", err)
	}
	// Named, because create ends by calling trust, whose own confirmation would
	// otherwise satisfy any test that only asks whether something was said.
	if !strings.Contains(created.stdout, "created") {
		t.Errorf("create did not say what it wrote:\nstdout: %q\nstderr: %q", created.stdout, created.stderr)
	}

	pruned := runIn(t, dir, home, "prune")
	if pruned.code != 0 {
		t.Fatalf("prune exited %d: %s", pruned.code, pruned.stderr)
	}
	if pruned.stdout == "" && pruned.stderr == "" {
		t.Error("prune said nothing about what it removed")
	}
}

// Usage has to stay off stdout: for export and hook that stream is eval'd, so
// text arriving there is executed rather than read.
func TestUsageGoesToStderr(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		// A command's own usage, and the top-level usage the Commander renders
		// for a name it does not know -- which is the one no in-process test can
		// see, since the Commander holds the streams it captured in init().
		{"a bad argument", []string{"hook", "fish"}},
		{"a bad argument to the command whose stdout is eval'd", []string{"export", "fish"}},
		{"an argument to a command that takes none", []string{"create", "extra"}},
		{"an unknown subcommand", []string{"nonesuch"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := run(t, tc.args...)
			if res.stderr == "" {
				t.Error("a usage error printed nothing to stderr")
			}
			// Emptiness rather than a phrase: the wording is not pinned here, and
			// looking for one would make this pass whenever the wording changed.
			if res.stdout != "" {
				t.Errorf("usage reached stdout, where the shell would eval it:\n%s", res.stdout)
			}
		})
	}
}

// The shim is only correct if a real shell accepts it. zoxide checks its own
// init output the same way; the CI installs zsh for the tests that already do
// this in the workspace package.
func TestTheShimLoadsInARealZsh(t *testing.T) {
	t.Parallel()
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
	dir, home := newHome(t)
	cmd := exec.CommandContext(ctx, zsh, "-f")
	cmd.Dir = dir
	cmd.Env = append(cleanEnv(), reentryKey+"=1", "HOME="+home)
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

func TestTheShimLoadsInARealBash(t *testing.T) {
	t.Parallel()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir, home := newHome(t)
	cmd := exec.CommandContext(ctx, bash, "--noprofile", "--norc")
	cmd.Dir = dir
	cmd.Env = append(cleanEnv(), reentryKey+"=1", "HOME="+home)
	cmd.Stdin = strings.NewReader(`eval "$(` + self + ` hook bash)"` + "\nprintf 'READY\\n'\n")
	cmd.WaitDelay = 5 * time.Second

	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("bash never finished:\n%s", out)
	}
	if err != nil {
		t.Fatalf("bash refused the shim: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "READY") {
		t.Errorf("the shell did not get past the shim:\n%s", out)
	}
}
