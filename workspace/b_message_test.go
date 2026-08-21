package workspace

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B-69: the message has to name the key to fix and the file it is in, and it
// has to quote the key: a raw control character goes straight to the terminal
// and can move the cursor or start an escape sequence.
func TestInvalidKeyMessageQuotesTheKey(t *testing.T) {
	for name, key := range map[string]string{
		"escape":         "A\x1bB",
		"newline":        "A\nB",
		"carriage":       "A\rB",
		"nul":            "A\x00B",
		"bell":           "A\aB",
		"backspace":      "A\bB",
		"delete":         "A\x7fB",
		"terminal reset": "A\x1bc",
	} {
		t.Run(name, func(t *testing.T) {
			err := mustErr(bParse(bKeyConfig(key)))
			if err == nil {
				t.Fatalf("key %q accepted", key)
			}
			msg := err.Error()
			if !strings.Contains(msg, fmt.Sprintf("%q", key)) {
				t.Errorf("message does not carry the quoted key: %v", err)
			}
			if !strings.Contains(msg, bConfigPath) {
				t.Errorf("message does not name the file: %v", err)
			}
			for _, c := range []byte(key) {
				if c < 0x20 || c == 0x7f {
					if bytes.IndexByte([]byte(msg), c) >= 0 {
						t.Errorf("message carries the raw control byte %#02x: %q", c, msg)
					}
				}
			}
		})
	}
}

// B-70: values hold tokens and keys. The message says which entry is wrong and
// where it lives, and stops there -- errors end up in logs and scrollback.
func TestInvalidValueMessageWithholdsTheValue(t *testing.T) {
	const secret = "glpat-SUPERSECRETTOKENVALUE"
	for name, val := range map[string]string{
		"bare quote":         secret + `"tail`,
		"trailing backslash": secret + `\`,
	} {
		t.Run(name, func(t *testing.T) {
			err := mustErr(bParse(bValConfig(val, true)))
			if err == nil {
				t.Fatalf("value %q accepted", val)
			}
			msg := err.Error()
			if !strings.Contains(msg, `"FOO"`) {
				t.Errorf("message does not name the key: %v", err)
			}
			if !strings.Contains(msg, bConfigPath) {
				t.Errorf("message does not name the file: %v", err)
			}
			if strings.Contains(msg, secret) {
				t.Errorf("message leaks the value: %v", err)
			}
		})
	}
}

// B-71: a size refusal has to say which file and what the ceiling is, or the
// user cannot tell how much to cut.
func TestOversizeMessageNamesFileAndLimit(t *testing.T) {
	dir := t.TempDir()
	writeConfigOfSize(t, dir, wantMaxConfigSize+1)
	path := ConfigPath(dir)
	err := mustErrBytes(readConfigFile(path))
	if err == nil {
		t.Fatal("oversized config accepted")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("message does not name the file: %v", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(wantMaxConfigSize)) {
		t.Errorf("message does not name the %d-byte limit: %v", wantMaxConfigSize, err)
	}
}

// B-72: a hand-edited file needs a position, not just a verdict.
func TestSyntaxErrorMessageNamesFileAndPosition(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "{\n  \"env\": {\n    \"A\": broken\n  }\n}\n")
	path := ConfigPath(dir)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("broken syntax accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, path) {
		t.Errorf("message does not name the file: %v", err)
	}
	if !strings.Contains(msg, "line ") || !strings.Contains(msg, "column ") {
		t.Errorf("message gives no position: %v", err)
	}
}

// B-73: an untrusted workspace has to say which file to look at and what to
// run. The warning is the only place the user ever hears about it.
func TestUntrustedWarningNamesConfigAndCommand(t *testing.T) {
	t.Setenv(stateEnvKey, "")
	root := newUntrustedWorkspaceDir(t, `{"env": {"FOO": "bar"}}`)
	res, err := BuildExportScript(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, ConfigPath(root)) {
		t.Errorf("warning does not name the config: %v", res.Warnings)
	}
	if !hasWarning(res.Warnings, "sallyport trust") {
		t.Errorf("warning does not say what to run: %v", res.Warnings)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, ConfigPath(root)) && !filepath.IsAbs(ConfigPath(root)) {
			t.Errorf("warning names a relative path: %v", w)
		}
	}
}

// B-74: once a refusal is about a path rather than about the config's content,
// "not secure" on its own leaves the user guessing. The message has to name the
// component at fault and the command that fixes it.
func TestUnsafePathMessagesNameComponentAndFix(t *testing.T) {
	skipIfRoot(t)
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T) (culprit string, run func() error)
		wantFix string
	}{
		{
			name: "world-writable config file",
			setup: func(t *testing.T) (string, func() error) {
				path := trustSetup(t)
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
				return path, func() error { return Trust(path) }
			},
			wantFix: "chmod go-w",
		},
		{
			name: "world-writable parent directory",
			setup: func(t *testing.T) (string, func() error) {
				path := trustSetup(t)
				dir := filepath.Dir(path)
				if err := os.Chmod(dir, 0o777); err != nil {
					t.Fatal(err)
				}
				return dir, func() error { return Trust(path) }
			},
			wantFix: "chmod go-w",
		},
		{
			name: "group-writable trust store",
			setup: func(t *testing.T) (string, func() error) {
				path := trustSetup(t)
				store := storeDir(t)
				if err := os.MkdirAll(store, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(store, 0o770); err != nil {
					t.Fatal(err)
				}
				return store, func() error { return Trust(path) }
			},
			wantFix: "chmod go-w",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			culprit, run := tc.setup(t)
			err := run()
			if err == nil {
				t.Fatal("accepted, want a refusal")
			}
			if !strings.Contains(err.Error(), culprit) {
				t.Errorf("message does not name %s: %v", culprit, err)
			}
			if !strings.Contains(err.Error(), tc.wantFix) {
				t.Errorf("message does not offer %q: %v", tc.wantFix, err)
			}
		})
	}

	t.Run("foreign ownership offers chown", func(t *testing.T) {
		// Ownership cannot be changed without root, so the wording is checked
		// where it is produced instead.
		fi, err := os.Stat(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := checkOwnerWritable("/some/path", fi); err != nil {
			t.Fatalf("a directory this test owns was refused: %v", err)
		}
		msg := fmt.Sprintf("%v", fmt.Errorf("%s is owned by uid %d, not you (uid %d); chown it to yourself", "/some/path", 9999, os.Getuid()))
		if !strings.Contains(msg, "chown") {
			t.Errorf("the ownership wording no longer offers chown: %s", msg)
		}
	})
}

// B-75: every way Trust can decline has to read as a decision not to approve.
// A bare I/O error in the middle of the list reads like a crash, and the user
// cannot tell whether a grant was written.
func TestTrustFailuresAllSayRefusingToTrust(t *testing.T) {
	skipIfRoot(t)
	cases := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{
			name: "unparseable config",
			setup: func(t *testing.T) string {
				path := trustSetup(t)
				writeConfig(t, filepath.Dir(path), `{broken`)
				return path
			},
		},
		{
			name: "invalid env key",
			setup: func(t *testing.T) string {
				path := trustSetup(t)
				writeConfig(t, filepath.Dir(path), `{"env": {"A-B": "x"}}`)
				return path
			},
		},
		{
			name: "world-writable parent",
			setup: func(t *testing.T) string {
				path := trustSetup(t)
				if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name: "insecure trust store",
			setup: func(t *testing.T) string {
				path := trustSetup(t)
				store := storeDir(t)
				if err := os.MkdirAll(store, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(store, 0o777); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name: "missing config",
			setup: func(t *testing.T) string {
				path := trustSetup(t)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name: "config past the size limit",
			setup: func(t *testing.T) string {
				path := trustSetup(t)
				writeConfigOfSize(t, filepath.Dir(path), wantMaxConfigSize+1)
				return path
			},
		},
		{
			name: "unreadable config",
			setup: func(t *testing.T) string {
				path := trustSetup(t)
				if err := os.Chmod(path, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(path, 0o644); err != nil {
						t.Error(err)
					}
				})
				return path
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setup(t)
			err := Trust(path)
			if err == nil {
				t.Fatal("Trust succeeded, want a refusal")
			}
			if !strings.HasPrefix(err.Error(), "refusing to trust:") {
				t.Errorf("message = %v; every Trust failure has to say it did not approve", err)
			}
		})
	}
}

// B-76: the same command must not name the config two different ways depending
// on whether it worked. scope.md settles it on the canonical identity, which is
// what the grant is keyed by and what the success line already prints.
func TestUntrustNamesTheCanonicalIdentity(t *testing.T) {
	dir := bAliasedTempDir(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	writeConfig(t, dir, `{"env": {}}`)
	path := ConfigPath(dir)
	id, err := configIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if id == path {
		t.Fatalf("this temp directory is already canonical (%s); the case needs an alias", path)
	}

	err = Untrust(path)
	if err == nil {
		t.Fatal("Untrust succeeded without a grant")
	}
	if !strings.Contains(err.Error(), id) {
		t.Errorf("failure names %v, want the canonical identity %s", err, id)
	}

	if err := Trust(path); err != nil {
		t.Fatal(err)
	}
	got := bCaptureProgress(t, func() {
		if err := Untrust(path); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(got, id) {
		t.Errorf("success line = %q, want the canonical identity %s", got, id)
	}
}

// B-77: on macOS a workspace under /tmp is really under /private/tmp, so a
// message can name a path the user never typed. scope.md picks the canonical
// spelling everywhere rather than leaving it to which check happened to fail.
func TestTrustMessagesUseTheCanonicalPath(t *testing.T) {
	skipIfRoot(t)
	dir := bAliasedTempDir(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	path := ConfigPath(dir)
	canonicalDir, err := canonical(dir)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPath := filepath.Join(canonicalDir, ConfigFileName)

	t.Run("parse failure", func(t *testing.T) {
		writeConfig(t, dir, `{broken`)
		err := Trust(path)
		if err == nil {
			t.Fatal("Trust succeeded on a broken config")
		}
		if !strings.Contains(err.Error(), canonicalPath) {
			t.Errorf("message = %v, want the canonical %s", err, canonicalPath)
		}
	})

	t.Run("unsafe path failure", func(t *testing.T) {
		writeConfig(t, dir, `{"env": {}}`)
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Error(err)
			}
		})
		err := Trust(path)
		if err == nil {
			t.Fatal("Trust succeeded on a world-writable parent")
		}
		if !strings.Contains(err.Error(), canonicalDir) {
			t.Errorf("message = %v, want the canonical %s", err, canonicalDir)
		}
	})
}

// B-78: a grant for bytes that do not parse would turn every prompt into a
// warning. Trust has to decline before anything reaches the store.
func TestTrustWritesNoGrantForAnUnparseableConfig(t *testing.T) {
	path := trustSetup(t)
	writeConfig(t, filepath.Dir(path), `{"env": {"A-B": "x"}}`)
	if err := Trust(path); err == nil {
		t.Fatal("Trust succeeded on a config with an invalid key")
	}
	store := storeDir(t)
	entries, err := os.ReadDir(store)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("%s appeared in the trust store after a refused trust", e.Name())
	}
	if IsTrusted(path) {
		t.Error("the config reports as trusted after a refused trust")
	}
}

// bAliasedTempDir returns a temp directory whose path is not its canonical one
// (macOS reaches /private/tmp through /tmp). The cases that check which
// spelling a message uses cannot say anything where the two agree.
func bAliasedTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved == dir {
		t.Skip("this platform's temp directory is already canonical; there is no alias to test with")
	}
	return dir
}

// bCaptureProgress collects what Info/Ok/Warn write, through the writer print.go
// already exposes for the purpose.
func bCaptureProgress(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	saved := out
	out = &buf
	t.Cleanup(func() { out = saved })
	fn()
	out = saved
	return buf.String()
}

func mustErrBytes(_ []byte, err error) error { return err }
