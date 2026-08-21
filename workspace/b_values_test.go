package workspace

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// B-21: strict mode single-quotes the value, so it can carry anything. Checking
// the content here would only reject values that are in fact fine, and the
// round-trip through zsh is what proves the quoting rather than the rendering.
func TestStrictModeCarriesAnyValueThroughZsh(t *testing.T) {
	values := map[string]string{
		"single quote":         `it's here`,
		"double quote":         `a"b`,
		"backslash":            `back\slash`,
		"newline":              "line1\nline2",
		"command substitution": `$(reboot)`,
		"backtick":             "`reboot`",
		"glob":                 `*`,
		"tilde":                `~`,
		"parameter":            `${x}`,
		"all at once":          "'\"\\\n$(reboot)`id`*~${x}",
	}
	for name, val := range values {
		t.Run(name, func(t *testing.T) {
			cfg, err := bParse(bValConfig(val, false))
			if err != nil {
				t.Fatalf("strict mode rejected %q: %v", val, err)
			}
			if cfg.Env["FOO"] != val {
				t.Fatalf("FOO = %q, want %q", cfg.Env["FOO"], val)
			}
			bWantStrictValueSurvivesZsh(t, map[string]string{"FOO": val})
		})
	}
}

// B-22: closing the quote, escaping the apostrophe, reopening the quote is the
// classic place to get single-quoting wrong, so the shapes that break a naive
// scheme are exercised on their own.
func TestStrictModeCarriesApostrophes(t *testing.T) {
	values := map[string]string{
		"one":      `o'brien`,
		"two":      `a''b`,
		"leading":  `'lead`,
		"trailing": `trail'`,
		"only":     `'`,
		"only two": `''`,
		"wrapped":  `'wrapped'`,
	}
	for name, val := range values {
		t.Run(name, func(t *testing.T) {
			cfg, err := bParse(bValConfig(val, false))
			if err != nil {
				t.Fatalf("strict mode rejected %q: %v", val, err)
			}
			if cfg.Env["FOO"] != val {
				t.Fatalf("FOO = %q, want %q", cfg.Env["FOO"], val)
			}
			bWantStrictValueSurvivesZsh(t, map[string]string{"FOO": val})
		})
	}
}

// B-23: JSON carries a NUL, the hook's `eval "$(...)"` does not -- command
// substitution drops it. Applying a value that differs from the approved bytes
// without saying so is the worst of the failure modes, so both modes refuse it.
func TestParseConfigRejectsNulInValue(t *testing.T) {
	for _, expand := range []bool{false, true} {
		mode := "strict"
		if expand {
			mode = "expand"
		}
		for name, val := range map[string]string{
			"alone":    "\x00",
			"trailing": "abc\x00",
			"leading":  "\x00abc",
			"middle":   "a\x00b",
		} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				_, err := bParse(bValConfig(val, expand))
				if err == nil {
					t.Fatalf("%s mode accepted a value holding a NUL; the shell would apply a different value than the one that was approved", mode)
				}
				if !strings.Contains(err.Error(), "FOO") || !strings.Contains(err.Error(), bConfigPath) {
					t.Errorf("message names neither the key nor the file: %v", err)
				}
			})
		}
	}
}

// B-24: a bare `"` closes the double-quoted string early and everything after it
// becomes a different statement.
func TestExpandModeRejectsBareDoubleQuote(t *testing.T) {
	for name, val := range map[string]string{
		"leading":  `"abc`,
		"middle":   `a"b`,
		"trailing": `abc"`,
		"only":     `"`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := bParse(bValConfig(val, true))
			if err == nil {
				t.Fatalf("expand mode accepted %q", val)
			}
			if !strings.Contains(err.Error(), `"FOO"`) || !strings.Contains(err.Error(), bConfigPath) {
				t.Errorf("message names neither the key nor the file: %v", err)
			}
		})
	}
}

// B-25: an escaped quote is legal double-quoted source text.
func TestExpandModeAcceptsEscapedDoubleQuote(t *testing.T) {
	for name, val := range map[string]string{
		"one":       `a\"b`,
		"two":       `a\"b\"c`,
		"leading":   `\"abc`,
		"trailing":  `abc\"`,
		"with pair": `a\\b\"c`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := bParse(bValConfig(val, true))
			if err != nil {
				t.Fatalf("expand mode rejected %q: %v", val, err)
			}
			if cfg.Env["FOO"] != val {
				t.Errorf("FOO = %q, want %q", cfg.Env["FOO"], val)
			}
		})
	}
}

// B-26: a trailing backslash eats the closing quote. Counting matters: an
// implementation that only looks at the last byte lets `\\\` through.
func TestExpandModeTrailingBackslashParity(t *testing.T) {
	for n := 1; n <= 5; n++ {
		val := "abc" + strings.Repeat(`\`, n)
		wantAccepted := n%2 == 0
		t.Run(fmt.Sprintf("%d backslashes", n), func(t *testing.T) {
			_, err := bParse(bValConfig(val, true))
			if wantAccepted && err != nil {
				t.Errorf("%d trailing backslashes rejected: %v", n, err)
			}
			if !wantAccepted && err == nil {
				t.Errorf("%d trailing backslashes accepted; the last one escapes the closing quote", n)
			}
		})
	}

	t.Run("a lone backslash is a trailing one", func(t *testing.T) {
		if _, err := bParse(bValConfig(`\`, true)); err == nil {
			t.Error("a value of a single backslash was accepted")
		}
	})
}

// B-27: escape state has to be tracked across the whole value; stepping through
// it wrongly hides a `"` that sits after an escaped backslash.
func TestExpandModeTracksEscapesThroughTheValue(t *testing.T) {
	cases := []struct {
		val      string
		accepted bool
	}{
		{`a\"b`, true},     // escaped quote
		{`a\\"b`, false},   // escaped backslash, then a bare quote
		{`a\\\"b`, true},   // escaped backslash, then an escaped quote
		{`a\\\\"b`, false}, // two escaped backslashes, then a bare quote
		{`a\\b\"c`, true},  // pair, then an escaped quote
		{`a\"b"c`, false},  // escaped quote, then a bare one
		{`\\`, true},       // a complete pair is not a trailing backslash
		{`a\\`, true},      //
		{`a\\\`, false},    // pair plus a dangling one
		{`\"`, true},       //
		{`"\"`, false},     // the first quote is bare
		{`a\nb`, true},     // an escape zsh gives meaning to, not our concern
		{`a\$b`, true},     //
	}
	for _, tc := range cases {
		t.Run(tc.val, func(t *testing.T) {
			_, err := bParse(bValConfig(tc.val, true))
			if tc.accepted && err != nil {
				t.Errorf("%q rejected: %v", tc.val, err)
			}
			if !tc.accepted && err == nil {
				t.Errorf("%q accepted", tc.val)
			}
		})
	}
}

// B-28: expand mode exists so the shell resolves the value at apply time.
// Refusing these would leave the mode with nothing to do. Tilde and glob are in
// the table with what they actually produce: inside double quotes zsh performs
// neither expansion, and the mode's contract is "double-quoted source text",
// not "expanded everywhere".
func TestExpandModeValuesExpandInZsh(t *testing.T) {
	zsh := bZsh(t)
	cases := []struct {
		name string
		val  string
		want string
	}{
		{"parameter", `$SALLYPORT_TEST_VAR`, "from-env"},
		{"braced with default", `${SALLYPORT_TEST_UNSET:-fallback}`, "fallback"},
		{"braced", `${SALLYPORT_TEST_VAR}`, "from-env"},
		{"command substitution", `$(printf sub)`, "sub"},
		{"backtick", "`printf tick`", "tick"},
		{"tilde stays literal in double quotes", `~`, "~"},
		{"glob stays literal in double quotes", `*`, "*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := bParse(bValConfig(tc.val, true))
			if err != nil {
				t.Fatalf("expand mode rejected %q: %v", tc.val, err)
			}
			script := renderScript(nil, WorkspaceVars("/ws", cfg), "")
			got := exportRunZshWithEnv(t, zsh, t.TempDir(), []string{"SALLYPORT_TEST_VAR=from-env"},
				"unset SALLYPORT_TEST_UNSET\n"+script+"\nprint -r -- \"GOT=$FOO\"\n")
			if !strings.Contains(got, "GOT="+tc.want+"\n") {
				t.Errorf("zsh read %q as something other than %q:\n%s", tc.val, tc.want, got)
			}
		})
	}
}

// B-29: history expansion is live in an interactive shell, but the hook hands
// the script to eval, and eval'd text is never a candidate for it. A value
// holding `!` must not blow up the prompt it lands on. The subtests are named
// without the bang on purpose: their names become temp directory paths, and a
// `!` in the path would be expanded by the very mechanism under test.
func TestExpandModeBangSurvivesInteractiveZsh(t *testing.T) {
	zsh := bZsh(t)
	cases := map[string]string{
		"middle":        `a!b`,
		"alone":         `!`,
		"doubled":       `!!`,
		"trailing":      `hello!`,
		"before a name": `a!$SALLYPORT_TEST_VAR`,
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := bParse(bValConfig(val, true))
			if err != nil {
				t.Fatalf("expand mode rejected %q: %v", val, err)
			}
			want := strings.ReplaceAll(val, "$SALLYPORT_TEST_VAR", "from-env")
			script := renderScript(nil, WorkspaceVars("/ws", cfg), "")
			got := bRunInteractiveZsh(t, zsh, []string{"SALLYPORT_TEST_VAR=from-env"}, script)
			if !strings.Contains(got, "GOT="+want+"\n") {
				t.Errorf("interactive zsh did not read %q as %q:\n%s", val, want, got)
			}
		})
	}

	// The control: typed straight at the prompt, the same text does expand.
	// Without it a shell that had history expansion switched off would pass the
	// cases above while proving nothing.
	t.Run("history expansion really is active", func(t *testing.T) {
		out := bRunZshStdin(t, zsh, t.TempDir(), nil, "print -r -- first\nprint -r -- \"GOT=!!\"\n")
		if strings.Contains(out, "GOT=!!") {
			t.Errorf("the shell did not history-expand a bang typed at the prompt, so the cases above are vacuous:\n%s", out)
		}
	})
}

// B-30: a raw newline is legal inside double quotes. A checker that reasons line
// by line about the generated script would reject a value that works.
func TestExpandModeAcceptsNewlineInValue(t *testing.T) {
	zsh := bZsh(t)
	const val = "line1\nline2\nline3"
	cfg, err := bParse(bValConfig(val, true))
	if err != nil {
		t.Fatalf("expand mode rejected a value with newlines: %v", err)
	}
	script := renderScript(nil, WorkspaceVars("/ws", cfg), "")
	bWantZshParses(t, zsh, script)
	got := exportRunZsh(t, zsh, t.TempDir(), script+"\nprint -r -- \"LINES=${(F)${(f)FOO}}\"\nprint -r -- \"COUNT=${#${(f)FOO}}\"\n")
	if !strings.Contains(got, "COUNT=3") {
		t.Errorf("the value did not arrive as one variable holding three lines:\n%s", got)
	}
}

// B-31: which bytes a value may hold is settled by covering all of them, not by
// listing the ones somebody thought of. Every code point from U+0000 to U+00FF
// goes through both modes; strict additionally has to hand the shell back the
// exact bytes.
func TestValueBytesAcrossBothModes(t *testing.T) {
	value := func(cp int) string { return "a" + string(rune(cp)) + "b" }

	t.Run("accepted and rejected bytes", func(t *testing.T) {
		for cp := 0; cp <= 0xFF; cp++ {
			for _, expand := range []bool{false, true} {
				// NUL never survives the hook's command substitution (B-23); a bare
				// double quote ends the expand-mode string early (B-24).
				wantAccepted := cp != 0x00 && (!expand || cp != '"')
				_, err := bParse(bValConfig(value(cp), expand))
				mode := "strict"
				if expand {
					mode = "expand"
				}
				if wantAccepted && err != nil {
					t.Errorf("%s: byte %#02x rejected: %v", mode, cp, err)
				}
				if !wantAccepted && err == nil {
					t.Errorf("%s: byte %#02x accepted", mode, cp)
				}
			}
		}
	})

	t.Run("strict values read back as one word", func(t *testing.T) {
		for cp := 1; cp <= 0xFF; cp++ {
			val := value(cp)
			script := renderScript(nil, []EnvVar{{Key: "V", Val: val, Literal: true}}, "")
			word, found := strings.CutPrefix(strings.TrimSuffix(script, "\n"), "export V=")
			if !found {
				t.Fatalf("byte %#02x: unexpected rendering %q", cp, script)
			}
			got, ok := exportReadZshWord(word)
			if !ok || got != val {
				t.Errorf("byte %#02x: rendered %s, which the shell reads as %q (one word: %v)", cp, word, got, ok)
			}
		}
	})

	t.Run("strict values survive real zsh", func(t *testing.T) {
		zsh := bZsh(t)
		var vars []EnvVar
		want := map[string]string{}
		for cp := 1; cp <= 0xFF; cp++ {
			name := fmt.Sprintf("V_%02X", cp)
			vars = append(vars, EnvVar{Key: name, Val: value(cp), Literal: true})
			want[name] = value(cp)
		}
		bWantStrictValueSurvivesZshVars(t, zsh, vars, want)
	})
}

// B-32: values have no length limit either. A cap picked for comfort would drop
// the long secrets and PATH-like values people actually keep in a config.
func TestParseConfigValueLength(t *testing.T) {
	for _, n := range []int{0, 1, 1 << 10, 1 << 16, 512 << 10} {
		val := strings.Repeat("v", n)
		cfg, err := bParse(bValConfig(val, false))
		if err != nil {
			t.Errorf("value of %d bytes rejected: %v", n, err)
			continue
		}
		if len(cfg.Env["FOO"]) != n {
			t.Errorf("value of %d bytes came back as %d", n, len(cfg.Env["FOO"]))
		}
	}
}

// B-33: a value of the wrong type has to be named, not dropped. Silently taking
// a number as the empty string leaves the user with a variable that is set and
// wrong, and no way to tell why.
func TestParseConfigRejectsNonStringValues(t *testing.T) {
	for name, src := range map[string]string{
		"number":  `{"env": {"FOO": 8080}}`,
		"boolean": `{"env": {"FOO": true}}`,
		"null":    `{"env": {"FOO": null}}`,
		"object":  `{"env": {"FOO": {}}}`,
		"array":   `{"env": {"FOO": []}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := bParse(src)
			if err == nil {
				t.Fatalf("a %s value was accepted as env %v", name, cfg.Env)
			}
			if !strings.Contains(err.Error(), bConfigPath) {
				t.Errorf("message does not name the file: %v", err)
			}
		})
	}
}

// B-34: encoding/json swaps an invalid UTF-8 byte for U+FFFD and carries on.
// scope.md keeps that; what it costs is pinned here, because the grant covers
// the bytes on disk while the shell receives the replaced ones.
func TestParseConfigReplacesInvalidUTF8InValue(t *testing.T) {
	raw := []byte("{\"env\": {\"FOO\": \"x\xffy\"}}")
	cfg, err := parseConfig(bConfigPath, raw)
	if err != nil {
		t.Fatalf("invalid UTF-8 in a value rejected: %v", err)
	}
	if cfg.Env["FOO"] != "x\uFFFDy" {
		t.Errorf("FOO = %q, want the byte replaced with U+FFFD", cfg.Env["FOO"])
	}
	if cfg.Env["FOO"] == "x\xffy" {
		t.Error("the raw byte survived; the rest of this test describes the replacement instead")
	}
	// The grant is taken over the file's bytes, so what was approved and what
	// gets applied are not the same string.
	if fingerprintBytes(bConfigPath, raw) == fingerprintBytes(bConfigPath, []byte("{\"env\": {\"FOO\": \"x\uFFFDy\"}}")) {
		t.Error("expected the approved bytes and the applied value to differ")
	}
}

// B-35: an empty value is a value. Applying it must set the variable to the
// empty string, and leaving must put back whatever was there before -- including
// the difference between "was empty" and "was not set".
func TestExportEmptyValueAppliesAndRestores(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	t.Setenv("SALLYPORT_EMPTY", "original")
	root := newWorkspaceDir(t, `{"env": {"SALLYPORT_EMPTY": ""}}`)

	enter := mustBuild(t, root, false)
	if !strings.Contains(enter, "export SALLYPORT_EMPTY=''\n") {
		t.Errorf("the empty value was not applied:\n%s", enter)
	}
	st := stateFromScript(t, enter)
	saved, ok := st.Saved["SALLYPORT_EMPTY"]
	if !ok || saved == nil || *saved != "original" {
		t.Fatalf("saved original = %v, want a pointer to \"original\"", saved)
	}

	setState(t, st)
	leave := mustBuild(t, bIsolatedTree(t), false)
	if !strings.Contains(leave, "export SALLYPORT_EMPTY='original'\n") {
		t.Errorf("leaving did not restore the original:\n%s", leave)
	}

	t.Run("in zsh", func(t *testing.T) {
		zsh := bZsh(t)
		got := exportRunZshWithEnv(t, zsh, root, []string{"SALLYPORT_EMPTY=original"},
			enter+"\nprint -r -- \"IN=[${SALLYPORT_EMPTY-<unset>}]\"\n"+leave+"\nprint -r -- \"OUT=[${SALLYPORT_EMPTY-<unset>}]\"\n")
		if !strings.Contains(got, "IN=[]") {
			t.Errorf("inside the workspace the variable is not the empty string:\n%s", got)
		}
		if !strings.Contains(got, "OUT=[original]") {
			t.Errorf("leaving did not restore the original:\n%s", got)
		}
	})
}

// bWantStrictValueSurvivesZsh renders vars as strict entries and checks the
// shell ends up holding those exact bytes.
func bWantStrictValueSurvivesZsh(t *testing.T, values map[string]string) {
	t.Helper()
	zsh := bZsh(t)
	var vars []EnvVar
	for k, v := range values {
		vars = append(vars, EnvVar{Key: k, Val: v, Literal: true})
	}
	bWantStrictValueSurvivesZshVars(t, zsh, vars, values)
}

// bWantStrictValueSurvivesZshVars compares through hex, so a value carrying a
// newline or a byte the terminal would swallow is still compared exactly. od
// reads the value from the shell's own memory, after the eval, which is the only
// place the answer means anything.
func bWantStrictValueSurvivesZshVars(t *testing.T, zsh string, vars []EnvVar, want map[string]string) {
	t.Helper()
	names := make([]string, 0, len(vars))
	for _, v := range vars {
		names = append(names, v.Key)
	}
	script := renderScript(nil, vars, "") + `
for __n in ` + strings.Join(names, " ") + `; do
  printf '%s=' "$__n"
  printf '%s' "${(P)__n}" | od -An -v -tx1 | tr -d ' \n'
  printf '\n'
done
`
	out := exportRunZsh(t, zsh, t.TempDir(), script)
	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if name, h, found := strings.Cut(line, "="); found {
			got[name] = h
		}
	}
	for name, val := range want {
		wantHex := hex.EncodeToString([]byte(val))
		if got[name] != wantHex {
			t.Errorf("%s: zsh holds %s, want %s (value %q)", name, got[name], wantHex, val)
		}
	}
}

// bRunInteractiveZsh applies a rendered script the way the hook does -- through
// eval, from a file -- in an interactive zsh started without rc files.
// Interactive is the point: history expansion is only active there, and -f keeps
// the developer's own .zshrc out of the result. Feeding the script's lines to
// the prompt directly would test the wrong thing, since the hook never does.
func bRunInteractiveZsh(t *testing.T, zsh string, env []string, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "script.zsh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	stdin := "eval \"$(<" + zshQuote(path) + ")\"\nprint -r -- \"GOT=$FOO\"\n"
	return bRunZshStdin(t, zsh, dir, env, stdin)
}

// bRunZshStdin runs an interactive, rc-less zsh over script on stdin. WaitDelay
// caps the wait on the pipe the way exportRunZsh does, so a script that opens a
// quote it never closes reports instead of hanging the test binary.
func bRunZshStdin(t *testing.T, zsh, dir string, env []string, script string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, zsh, "-i", "-f")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader(script)
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("interactive zsh never finished:\n%s", out)
	}
	if err != nil {
		t.Fatalf("interactive zsh failed: %v\n%s", err, out)
	}
	return string(out)
}
