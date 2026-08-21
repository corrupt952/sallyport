package workspace

import (
	"fmt"
	"strings"
	"testing"
)

// B-01: the POSIX Name forms a config may legitimately use must keep loading.
func TestParseConfigAcceptsPosixNameKeys(t *testing.T) {
	for _, key := range []string{"A", "_", "_A1", "Z9_z", "A_B_C", "a", "__", "A0", "_0"} {
		cfg, err := bParse(bKeyConfig(key))
		if err != nil {
			t.Errorf("key %q rejected: %v", key, err)
			continue
		}
		if cfg.Env[key] != "x" {
			t.Errorf("key %q parsed to %v", key, cfg.Env)
		}
	}
}

// B-02: a key that is not a shell identifier would change what the export
// statement means, so every non-identifier shape has to be named and refused.
func TestParseConfigRejectsNonIdentifierKeys(t *testing.T) {
	for _, key := range []string{"1A", "9", "-A", ".A", "A-B", "A.B", "A B", "A/B", "A:B", "A+B", "A=B"} {
		bWantInvalidKey(t, key, mustErr(bParse(bKeyConfig(key))))
	}
}

// B-03: `export =v` is a syntax error, so the empty key cannot be let through.
func TestParseConfigRejectsEmptyKey(t *testing.T) {
	bWantInvalidKey(t, "", mustErr(bParse(bKeyConfig(""))))
}

// B-04: keys reach the export statement unquoted, so key validation is the only
// thing standing between a config and shell injection.
func TestParseConfigRejectsShellMetacharacterKeys(t *testing.T) {
	for _, key := range []string{
		"A;export EVIL=1", "A$(id)", "A`id`", "A|B", "A&&B", "A>f", "A<f",
		"A#c", "A{", "A(", "A*", "A?", "A[", "A]", "A~", "A!",
	} {
		bWantInvalidKey(t, key, mustErr(bParse(bKeyConfig(key))))
	}
}

// B-05: Go's `$` does not match before a trailing newline unless (?m) is set, so
// "A\n" is refused today. Anything that loosens the anchoring -- (?m), dropping
// the anchors, FindString instead of MatchString -- turns one extra line in a
// config into an injected command, which is what this pins.
func TestParseConfigRejectsNewlineAndCarriageReturnKeys(t *testing.T) {
	for _, key := range []string{"A\nB", "A\n", "\nA", "A\r", "A\rB", "A\n\rB", "A\r\n"} {
		bWantInvalidKey(t, key, mustErr(bParse(bKeyConfig(key))))
	}
}

// B-06: control characters are not identifiers, and a NUL truncates the script
// the shell is handed at the point it appears.
func TestParseConfigRejectsControlCharacterKeys(t *testing.T) {
	for _, key := range []string{"A\tB", "A　B", "A\x00B", "A\x00", "A\x7f", "A\x1bB", "A\vB", "A\fB"} {
		bWantInvalidKey(t, key, mustErr(bParse(bKeyConfig(key))))
	}
}

// B-07: zsh does not accept non-ASCII variable names, and two keys that look
// identical on screen cannot be told apart by the human approving the config.
func TestParseConfigRejectsNonASCIIKeys(t *testing.T) {
	for _, key := range []string{
		"Aé",       // Ae with acute
		"Ａ",        // fullwidth A
		"Ω",        // capital omega
		"Á",       // A plus a combining acute accent
		"A\u200dB", // zero-width joiner between two valid halves
		"Ａ_B",      // fullwidth A followed by legal bytes
		"Ⅵ",        // roman numeral six, which folds to "vi"
	} {
		bWantInvalidKey(t, key, mustErr(bParse(bKeyConfig(key))))
	}
}

// B-08: validation happens on the decoded key, not on the source bytes, so a key
// spelled with JSON escapes is the key it decodes to.
func TestParseConfigValidatesDecodedKeyNotSourceBytes(t *testing.T) {
	// The source spells AB entirely in \u escapes, so nothing in the raw bytes
	// looks like an identifier: a check against the source text would reject it.
	cfg, err := bParse("{\"env\": {\"\\u0041\\u0042\": \"x\"}}")
	if err != nil {
		t.Fatalf("escaped spelling of a valid key rejected: %v", err)
	}
	if cfg.Env["AB"] != "x" {
		t.Errorf("env = %v, want the key decoded to AB", cfg.Env)
	}
	// The same route must not smuggle an invalid key past the check.
	bWantInvalidKey(t, "A B", mustErr(bParse("{\"env\": {\"A\\u0020B\": \"x\"}}")))
	bWantInvalidKey(t, "A\x00B", mustErr(bParse("{\"env\": {\"A\\u0000B\": \"x\"}}")))
}

// B-09: encoding/json replaces an invalid UTF-8 byte with U+FFFD, and keyRe then
// refuses the replacement character. The rejection is real but indirect, so it
// is pinned here: an implementation that stopped replacing would open the hole.
func TestParseConfigRejectsInvalidUTF8Key(t *testing.T) {
	// The raw 0xff cannot go through quoteJSON, which would sanitize it away.
	_, err := parseConfig(bConfigPath, []byte("{\"env\": {\"A\xffB\": \"x\"}}"))
	bWantInvalidKey(t, "A�B", err)
}

// B-10: there is no length limit on keys, and inventing one would drop keys that
// are perfectly legal. The rejection message must not echo a whole long key back
// to the terminal either.
func TestParseConfigKeyLength(t *testing.T) {
	for _, n := range []int{1, 2, 255, 256, 1024, 4096, 65536} {
		key := "A" + strings.Repeat("b", n-1)
		cfg, err := bParse(bKeyConfig(key))
		if err != nil {
			t.Errorf("valid key of %d bytes rejected: %v", n, err)
			continue
		}
		if cfg.Env[key] != "x" {
			t.Errorf("key of %d bytes did not survive the parse", n)
		}
	}

	t.Run("rejection does not dump the whole key", func(t *testing.T) {
		key := "A" + strings.Repeat("b", 65535) + "-"
		err := mustErr(bParse(bKeyConfig(key)))
		if err == nil {
			t.Fatal("invalid long key accepted")
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("message carries the whole %d-byte key (%d bytes of message); it has to be elided", len(key), len(err.Error()))
		}
	})
}

// B-11: the check must cover every entry. Each layout runs repeatedly because Go
// randomizes map iteration order: an implementation that stops at the first
// entry would otherwise pass by luck.
func TestParseConfigRejectsInvalidKeyAtAnyPosition(t *testing.T) {
	const bad = "A-B"
	build := func(pos, n int) string {
		entries := make([]string, 0, n+1)
		for i := 0; i < n; i++ {
			entries = append(entries, fmt.Sprintf("%s: %q", quoteJSON(fmt.Sprintf("VALID_%03d", i)), "v"))
		}
		entry := quoteJSON(bad) + `: "v"`
		entries = append(entries[:pos:pos], append([]string{entry}, entries[pos:]...)...)
		return `{"env": {` + strings.Join(entries, ", ") + `}}`
	}
	cases := map[string]string{
		"alone":  build(0, 0),
		"first":  build(0, 50),
		"middle": build(25, 50),
		"last":   build(50, 50),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			// 50 parses: one pass proves nothing when iteration order is random.
			for i := 0; i < 50; i++ {
				if _, err := bParse(src); err == nil {
					t.Fatalf("invalid key %q accepted on parse %d", bad, i)
				}
			}
		})
	}
}

// B-12: with more than one invalid key the reported one must not depend on map
// iteration order. A user who fixes the key the message named and reruns has to
// see progress, not a different key out of the same file.
func TestParseConfigReportsTheSameInvalidKeyEveryTime(t *testing.T) {
	src := `{"env": {"A-B": "1", "C.D": "2", "1E": "3", "F/G": "4"}}`
	first := mustErr(bParse(src))
	if first == nil {
		t.Fatal("config with four invalid keys accepted")
	}
	for i := 0; i < 100; i++ {
		got := mustErr(bParse(src))
		if got == nil {
			t.Fatalf("parse %d accepted the config", i)
		}
		if got.Error() != first.Error() {
			t.Fatalf("parse %d reported %v, parse 0 reported %v; the reported key follows map iteration order", i, got, first)
		}
	}
}

// B-13: the rendered script has to be byte-identical across runs at every size,
// or the state fingerprint stops matching and every prompt reapplies.
func TestConfigToScriptIsDeterministicAtEverySize(t *testing.T) {
	for _, n := range []int{0, 1, 2, 100, 1000} {
		t.Run(fmt.Sprintf("%d entries", n), func(t *testing.T) {
			entries := make([]string, 0, n)
			for i := 0; i < n; i++ {
				entries = append(entries, fmt.Sprintf(`"K_%04d": "v%d"`, i, i))
			}
			src := `{"env": {` + strings.Join(entries, ", ") + `}}`

			render := func() string {
				cfg, err := bParse(src)
				if err != nil {
					t.Fatalf("%d entries rejected: %v", n, err)
				}
				return renderScript(nil, WorkspaceVars("/ws", cfg), "")
			}
			first := render()
			// 100 renders: one map iteration order is not evidence of stability.
			for i := 0; i < 100; i++ {
				if got := render(); got != first {
					t.Fatalf("render %d differs from render 0", i)
				}
			}

			cfg, err := bParse(src)
			if err != nil {
				t.Fatal(err)
			}
			vars := WorkspaceVars("/ws", cfg)
			if len(vars) != n+1 {
				t.Fatalf("got %d vars, want %d plus WORKSPACE_PATH", len(vars), n)
			}
			if vars[0].Key != "WORKSPACE_PATH" {
				t.Errorf("vars[0] = %q, want WORKSPACE_PATH first", vars[0].Key)
			}
			// WORKSPACE_PATH is prepended, so ordering starts at the config's own
			// entries.
			for i := 2; i < len(vars); i++ {
				if vars[i-1].Key > vars[i].Key {
					t.Fatalf("config keys are not ascending at %d: %q then %q", i, vars[i-1].Key, vars[i].Key)
				}
			}
		})
	}
}

// B-14: encoding/json takes the last of two entries with the same key, without a
// word. scope.md keeps that (rejecting would split the handling across the
// hujson layer for no proportional gain), so the behaviour is pinned here rather
// than changed.
func TestParseConfigDuplicateEnvKeyTakesTheLast(t *testing.T) {
	cfg, err := bParse(`{"env": {"A": "1", "A": "2"}}`)
	if err != nil {
		t.Fatalf("duplicate key rejected: %v", err)
	}
	if cfg.Env["A"] != "2" {
		t.Errorf("A = %q, want the last entry to win", cfg.Env["A"])
	}
	if len(cfg.Env) != 1 {
		t.Errorf("env = %v, want a single entry", cfg.Env)
	}
}

// B-15: same rule one level up, for a repeated "env" object. The last one
// replaces the first rather than merging into it, which is what decoding a
// member at a time gives and the same answer a duplicate key inside env gets.
func TestParseConfigDuplicateEnvObjectTakesTheLastOne(t *testing.T) {
	cfg, err := bParse(`{"env": {"A": "1"}, "env": {"B": "2"}}`)
	if err != nil {
		t.Fatalf("duplicate env object rejected: %v", err)
	}
	if _, ok := cfg.Env["A"]; ok {
		t.Errorf("env = %v, want only the last object's entries", cfg.Env)
	}
	if cfg.Env["B"] != "2" {
		t.Errorf("B = %q, want the last object to win", cfg.Env["B"])
	}

	cfg, err = bParse(`{"env": {"A": "1"}, "env": {"A": "2"}}`)
	if err != nil {
		t.Fatalf("duplicate env object rejected: %v", err)
	}
	if cfg.Env["A"] != "2" {
		t.Errorf("A = %q, want the last object to win for a repeated key", cfg.Env["A"])
	}
}

// B-16: environment variable names are case-sensitive, and folding them would
// merge two variables the user meant to keep apart.
func TestParseConfigKeysAreCaseSensitive(t *testing.T) {
	cfg, err := bParse(`{"env": {"path": "lower", "PATH": "upper", "Path": "mixed"}}`)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"path": "lower", "PATH": "upper", "Path": "mixed"} {
		if cfg.Env[key] != want {
			t.Errorf("%s = %q, want %q", key, cfg.Env[key], want)
		}
	}
	if vars := WorkspaceVars("/ws", cfg); len(vars) != 4 {
		t.Fatalf("got %d vars, want WORKSPACE_PATH plus three distinct keys: %v", len(vars), vars)
	}
}

// B-17: an explicit WORKSPACE_PATH replaces the automatic one instead of joining
// it, in both modes, and under expand it is the user's value that gets expanded.
func TestWorkspaceVarsExplicitWorkspacePathInBothModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		src     string
		literal bool
	}{
		{"strict", `{"env": {"WORKSPACE_PATH": "/custom"}}`, true},
		{"expand", `{"expand": true, "env": {"WORKSPACE_PATH": "/custom"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := bParse(tc.src)
			if err != nil {
				t.Fatal(err)
			}
			vars := WorkspaceVars("/ws", cfg)
			want := EnvVar{Key: "WORKSPACE_PATH", Val: "/custom", Literal: tc.literal}
			if len(vars) != 1 || vars[0] != want {
				t.Fatalf("vars = %v, want exactly %v", vars, want)
			}
			wantLine := "export WORKSPACE_PATH='/custom'\n"
			if !tc.literal {
				wantLine = "export WORKSPACE_PATH=\"/custom\"\n"
			}
			if script := renderScript(nil, vars, ""); script != wantLine {
				t.Errorf("script = %q, want %q", script, wantLine)
			}
		})
	}
}

// B-18: sallyport keeps no deny-list of key names. The trust grant is the
// boundary, and a trusted config already decides PATH; pinning this makes any
// future deny-list a deliberate decision rather than a silent one.
func TestParseConfigHasNoKeyDenyList(t *testing.T) {
	for _, key := range []string{"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "IFS", "PS1", "SHELL", "HOME", "DYLD_INSERT_LIBRARIES"} {
		cfg, err := bParse(bKeyConfig(key))
		if err != nil {
			t.Errorf("key %q rejected: %v", key, err)
			continue
		}
		if cfg.Env[key] != "x" {
			t.Errorf("key %q did not survive the parse", key)
		}
	}
}

// B-19: a config may name the state variables, but it must not get to decide
// what leaving the workspace restores. The state line is emitted after the
// config's exports, so the real state is what the shell ends up holding.
func TestExportConfigCannotForgeState(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newWorkspaceDir(t, `{"env": {"`+stateEnvKey+`": "forged-env", "`+stateShellVar+`": "forged-shell"}}`)
	script := mustBuild(t, root, false)

	forged := "export " + stateShellVar + "='forged-shell'"
	real := "typeset -g " + stateShellVar + "="
	if !strings.Contains(script, forged) {
		t.Fatalf("the config entry was not applied at all:\n%s", script)
	}
	if strings.Index(script, forged) > strings.Index(script, real) {
		t.Errorf("the config's assignment comes after the state line, so it decides the state:\n%s", script)
	}
	if st := stateFromScript(t, script); st.Root != root {
		t.Errorf("state root = %q, want %q", st.Root, root)
	}

	t.Run("in zsh", func(t *testing.T) {
		zsh := bZsh(t)
		encoded, err := encodeState(stateFromScript(t, script))
		if err != nil {
			t.Fatal(err)
		}
		got := exportRunZsh(t, zsh, root, script+"\nprint -r -- \"STATE=$"+stateShellVar+"\"\n")
		if !strings.Contains(got, "STATE="+encoded) {
			t.Errorf("the shell state is not sallyport's own blob:\n%s", got)
		}
	})
}

// B-20: `export export=1` is legal shell. Refusing a key because it collides
// with a shell keyword would drop a config that works.
func TestParseConfigAcceptsShellKeywordKeys(t *testing.T) {
	keys := []string{"export", "unset", "typeset", "local", "if", "then", "function", "do"}
	entries := make([]string, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, quoteJSON(k)+`: "v"`)
	}
	cfg, err := bParse(`{"env": {` + strings.Join(entries, ", ") + `}}`)
	if err != nil {
		t.Fatalf("shell keyword keys rejected: %v", err)
	}
	for _, k := range keys {
		if cfg.Env[k] != "v" {
			t.Errorf("key %q did not survive the parse", k)
		}
	}
	bWantZshParses(t, bZsh(t), renderScript(nil, WorkspaceVars("/ws", cfg), ""))
}

// mustErr drops the config a parse returned so a rejection can be asserted on
// one line.
func mustErr(_ Config, err error) error { return err }
