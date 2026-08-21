package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B-79: renderScript trusts its input. Handed a key keyRe would have refused, it
// emits shell that runs a second command, and this records that outcome rather
// than asserting it away: keyRe is the whole defence, and anyone loosening it
// should be able to read here what that costs.
func TestRenderScriptTrustsItsKeysWhichIsWhyKeyReExists(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "injected")
	key := "A; touch " + marker + "; X"

	if keyRe.MatchString(key) {
		t.Fatalf("keyRe accepts %q; the case describes a key it is meant to refuse", key)
	}
	if _, err := bParse(bKeyConfig(key)); err == nil {
		t.Fatal("parseConfig accepted the key; nothing else stops it from reaching renderScript")
	}

	script := renderScript(nil, []EnvVar{{Key: key, Val: "v", Literal: true}}, "")
	want := "export " + key + "='v'\n"
	if script != want {
		t.Fatalf("script = %q, want %q", script, want)
	}

	zsh := bZsh(t)
	exportRunZsh(t, zsh, dir, script)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the injected command did not run (%v); if that is because renderScript now validates keys, this case needs rewriting rather than deleting", err)
	}
	t.Log("the key ran as a second command, as documented: keyRe in parseConfig is the only thing preventing this")
}

// B-80: saved keys land in the same place config keys do -- the left side of
// export and unset -- and they arrive from a shell variable an outside process
// may have set. A blob carrying a key sallyport could not have written is not
// state, whatever else is in it.
func TestForgedStateKeyIsDiscardedNotEmitted(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwn")
	root := newWorkspaceDir(t, `{"env": {"FOO": "bar"}}`)

	for name, key := range map[string]string{
		"command separator": "X; touch " + marker,
		"substitution":      "X$(touch " + marker + ")",
		"newline":           "X\ntouch " + marker,
	} {
		t.Run(name, func(t *testing.T) {
			blob := fmt.Sprintf(`{"root":%s,"saved":{%s:null},"schema":%q}`,
				quoteJSON(root), quoteJSON(key), stateSchema)
			exportSetRawState(t, blob)

			res, err := BuildExportScript(root, false)
			if err != nil {
				t.Fatal(err)
			}
			if !hasWarning(res.Warnings, corruptStateWarning) {
				t.Errorf("a forged saved key was accepted without a warning: %v", res.Warnings)
			}
			if strings.Contains(res.Script, "touch") {
				t.Fatalf("the forged key reached the script:\n%s", res.Script)
			}
			if strings.Contains(res.Script, marker) {
				t.Fatalf("the forged key reached the script:\n%s", res.Script)
			}

			zsh := bZsh(t)
			exportRunZsh(t, zsh, dir, res.Script)
			if _, err := os.Stat(marker); err == nil {
				t.Error("the forged key ran as a command")
			}
		})
	}
}

// B-81: the hook evals the whole script as one unit, so one malformed line
// fails everything, the state commit included, and the shell is left holding a
// state it can no longer move off. Every shape the renderer can produce goes
// through the shell's own parser.
func TestEveryRenderedScriptShapeParsesInZsh(t *testing.T) {
	zsh := bZsh(t)
	// Values chosen to exercise the quoting rather than to be tame: an
	// apostrophe, a metacharacter and a newline in the literal set, and legal
	// double-quoted source in the expand set.
	literalValues := []string{`plain`, `it's $HOME`, "a\nb", "back\\slash", `a"b`, "`id`"}
	expandValues := []string{`plain`, `$HOME/x`, `${VAR:-d}`, `a\"b`, `a\\b`, `$(printf x)`}

	for _, count := range []int{0, 1, 1000} {
		for _, expand := range []bool{false, true} {
			for _, withRestores := range []bool{false, true} {
				for _, withState := range []bool{false, true} {
					mode := "strict"
					values := literalValues
					if expand {
						mode = "expand"
						values = expandValues
					}
					name := fmt.Sprintf("%s/%d vars/restores=%v/state=%v", mode, count, withRestores, withState)
					t.Run(name, func(t *testing.T) {
						vars := make([]EnvVar, 0, count)
						for i := 0; i < count; i++ {
							vars = append(vars, EnvVar{
								Key:     fmt.Sprintf("V_%04d", i),
								Val:     values[i%len(values)],
								Literal: !expand,
							})
						}
						var saved map[string]*string
						if withRestores {
							saved = map[string]*string{}
							for i := 0; i < count; i++ {
								if i%2 == 0 {
									v := literalValues[i%len(literalValues)]
									saved[fmt.Sprintf("V_%04d", i)] = &v
								} else {
									saved[fmt.Sprintf("V_%04d", i)] = nil
								}
							}
							// A restore with nothing to apply is the shape leaving
							// a workspace produces.
							one := "prior"
							saved["ALWAYS_RESTORED"] = &one
							saved["ALWAYS_UNSET"] = nil
						}
						stateLine := ""
						if withState {
							encoded, err := encodeState(state{Root: "/ws", Fingerprint: "abc", Saved: saved})
							if err != nil {
								t.Fatal(err)
							}
							stateLine = fmt.Sprintf("typeset -g %s=%s\n", stateShellVar, zshQuote(encoded))
						}
						bWantZshParses(t, zsh, renderScript(saved, vars, stateLine))
					})
				}
			}
		}
	}
}

// B-82: nothing changed between two prompts has to render byte for byte the
// same, or the fingerprint comparison misses and the whole transition reruns on
// every prompt.
func TestRenderScriptIsByteIdenticalAcrossRuns(t *testing.T) {
	saved := map[string]*string{}
	var vars []EnvVar
	for i := 0; i < 200; i++ {
		key := fmt.Sprintf("K_%03d", i)
		if i%3 == 0 {
			saved[key] = nil
		} else {
			v := fmt.Sprintf("old%d", i)
			saved[key] = &v
		}
		vars = append(vars, EnvVar{Key: key, Val: fmt.Sprintf("new%d", i), Literal: i%2 == 0})
	}
	stateLine := "typeset -g " + stateShellVar + "='ENC'\n"

	first := renderScript(saved, vars, stateLine)
	// 100 renders: a single map iteration order says nothing about stability.
	for i := 0; i < 100; i++ {
		if got := renderScript(saved, vars, stateLine); got != first {
			t.Fatalf("render %d differs from render 0", i)
		}
	}
}

// B-83: on a workspace-to-workspace switch the old values are put back first and
// the new ones applied after, so a key both workspaces set ends on the new
// value. The other order leaves the previous workspace's value in place.
func TestSwitchRestoresBeforeApplying(t *testing.T) {
	orig := "from-outside"
	saved := map[string]*string{"SHARED": &orig, "ONLY_OLD": &orig}
	vars := []EnvVar{
		{Key: "SHARED", Val: "from-new", Literal: true},
		{Key: "ONLY_NEW", Val: "new", Literal: true},
	}
	script := renderScript(saved, vars, "")
	restore := strings.Index(script, "export SHARED='from-outside'")
	apply := strings.Index(script, "export SHARED='from-new'")
	if restore < 0 || apply < 0 {
		t.Fatalf("both lines for SHARED must be present:\n%s", script)
	}
	if restore > apply {
		t.Errorf("the restore comes after the apply, so the switch ends on the old value:\n%s", script)
	}

	t.Run("end to end", func(t *testing.T) {
		t.Setenv(stateEnvKey, "")
		t.Setenv("SHARED", "from-outside")
		old := newWorkspaceDir(t, `{"env": {"SHARED": "from-old", "ONLY_OLD": "o"}}`)
		enter := mustBuild(t, old, false)
		setState(t, stateFromScript(t, enter))

		newRoot := exportUntrustedWorkspaceDirNamed(t, "other", `{"env": {"SHARED": "from-new", "ONLY_NEW": "n"}}`)
		if err := Trust(ConfigPath(newRoot)); err != nil {
			t.Fatal(err)
		}
		switchScript := mustBuild(t, newRoot, false)

		zsh := bZsh(t)
		got := exportRunZshWithEnv(t, zsh, newRoot, []string{"SHARED=from-outside"},
			enter+"\n"+switchScript+`
print -r -- "SHARED=$SHARED"
print -r -- "ONLY_OLD=${ONLY_OLD-<unset>}"
print -r -- "ONLY_NEW=${ONLY_NEW-<unset>}"
`)
		for _, want := range []string{"SHARED=from-new", "ONLY_OLD=<unset>", "ONLY_NEW=n"} {
			if !strings.Contains(got, want) {
				t.Errorf("zsh output missing %q:\n%s", want, got)
			}
		}
	})
}
