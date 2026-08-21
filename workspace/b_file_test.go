package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// B-36: both sides of the limit. Without them a `>` written as `>=` survives.
func TestReadConfigFileSizeBoundary(t *testing.T) {
	for _, tc := range []struct {
		size     int
		accepted bool
	}{
		{wantMaxConfigSize - 1, true},
		{wantMaxConfigSize, true},
		{wantMaxConfigSize + 1, false},
	} {
		t.Run(fmt.Sprintf("%d bytes", tc.size), func(t *testing.T) {
			dir := t.TempDir()
			writeConfigOfSize(t, dir, tc.size)
			path := ConfigPath(dir)
			data, err := readConfigFile(path)
			if tc.accepted {
				if err != nil {
					t.Fatalf("config of %d bytes rejected: %v", tc.size, err)
				}
				if len(data) != tc.size {
					t.Errorf("read %d bytes, want %d", len(data), tc.size)
				}
				return
			}
			if err == nil {
				t.Fatalf("config of %d bytes accepted", tc.size)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("message does not name the file: %v", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(wantMaxConfigSize)) {
				t.Errorf("message does not name the limit: %v", err)
			}
		})
	}
}

// B-37: the limit exists to bound what every prompt costs, which only holds if
// the size decides before the read. A gigabyte config has to be refused as
// cheaply as a two-megabyte one.
func TestReadConfigFileRefusesLargeFilesWithoutReadingThem(t *testing.T) {
	sizes := []int64{2 << 20, 16 << 20, 1 << 30}
	var slowest time.Duration
	for _, size := range sizes {
		dir := t.TempDir()
		path := ConfigPath(dir)
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		// Sparse: the bytes are never written, so the file costs nothing on disk
		// but still reports its full size to Stat.
		if err := f.Truncate(size); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		start := time.Now()
		_, err = readConfigFile(path)
		elapsed := time.Since(start)
		if err == nil {
			t.Errorf("%d bytes accepted", size)
			continue
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("%d bytes rejected for the wrong reason: %v", size, err)
		}
		if elapsed > slowest {
			slowest = elapsed
		}
	}
	// Reading a gigabyte takes far longer than this even from page cache, so a
	// refusal inside the budget is evidence the file was never opened.
	if slowest > time.Second {
		t.Errorf("the slowest refusal took %v; the size is not being checked before the read", slowest)
	}
}

// B-38, B-39: a config that parses to nothing is a config the user got wrong.
// Reading it as "no env" would let a truncated write through in silence.
func TestParseConfigRejectsEmptyAndCommentOnlyFiles(t *testing.T) {
	for name, src := range map[string]string{
		"empty":              "",
		"whitespace only":    "   \n\t\n",
		"line comment only":  "// nothing here\n",
		"block comment only": "/* nothing here */\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := bParse(src)
			if err == nil {
				t.Fatal("accepted, want a rejection")
			}
			if !strings.Contains(err.Error(), bConfigPath) {
				t.Errorf("message does not name the file: %v", err)
			}
		})
	}
}

// B-40: a FIFO named .sallyport.jsonc must neither mark a workspace nor make an
// open block. The hook runs on every prompt; a blocked open freezes the shell.
func TestConfigFifoNeitherMarksARootNorBlocks(t *testing.T) {
	dir := bIsolatedTree(t)
	path := ConfigPath(dir)
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}

	if got := FindRoot(dir); got != "" {
		t.Errorf("FindRoot = %q, want empty: a FIFO is not a regular file", got)
	}

	done := make(chan error, 1)
	go func() {
		_, err := LoadConfig(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("LoadConfig succeeded on a FIFO")
		}
	case <-time.After(5 * time.Second):
		// The goroutine stays blocked on the open for the life of the test
		// binary; nothing can unblock it without a writer.
		t.Fatal("LoadConfig blocked on a FIFO; on the hook path that is a frozen shell")
	}
}

// B-41: a directory carrying the config's name is not a workspace marker, and
// reading it fails rather than yielding an empty config.
func TestConfigDirectoryIsNotAWorkspace(t *testing.T) {
	dir := bIsolatedTree(t)
	if err := os.Mkdir(ConfigPath(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(dir); got != "" {
		t.Errorf("FindRoot = %q, want empty", got)
	}
	if _, err := LoadConfig(ConfigPath(dir)); err == nil {
		t.Error("LoadConfig succeeded on a directory")
	}
}

// B-42: a config pointed at an endless device would be read until memory ran
// out, so the character device has to fail the regular-file test.
func TestConfigSymlinkToCharacterDeviceIsNotAWorkspace(t *testing.T) {
	dir := bIsolatedTree(t)
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("/dev/zero not available")
	}
	if err := os.Symlink("/dev/zero", ConfigPath(dir)); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(dir); got != "" {
		t.Errorf("FindRoot = %q, want empty", got)
	}
}

// B-43: an unreadable config still marks the workspace -- Stat succeeds, so the
// directory is one -- and every path that then tries to read it has to say so
// by name instead of behaving as if no config existed.
func TestUnreadableConfigIsReportedNotIgnored(t *testing.T) {
	skipIfRoot(t)
	t.Setenv(stateEnvKey, "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := bIsolatedTree(t)
	writeConfig(t, dir, `{"env": {"FOO": "bar"}}`)
	path := ConfigPath(dir)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Error(err)
		}
	})

	if got := FindRoot(dir); got != dir {
		t.Errorf("FindRoot = %q, want %q: Stat succeeds, so the marker is there", got, dir)
	}
	err := Trust(path)
	if err == nil {
		t.Error("Trust succeeded on an unreadable config")
	} else if !strings.Contains(err.Error(), path) {
		t.Errorf("Trust message does not name the file: %v", err)
	}

	res, err := BuildExportScript(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "ignoring broken") {
		t.Errorf("export gave no warning for an unreadable config: %v", res.Warnings)
	}
	if !hasWarning(res.Warnings, dir) {
		t.Errorf("export warning does not name the workspace: %v", res.Warnings)
	}
}

// B-44: a broken link is not a workspace marker, and the search has to carry on
// past it rather than stopping at the directory that holds it.
func TestFindRootSkipsDanglingSymlinkAndKeepsClimbing(t *testing.T) {
	base := bIsolatedTree(t)
	parent := filepath.Join(base, "parent")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, parent, `{"env": {}}`)
	if err := os.Symlink(filepath.Join(base, "does-not-exist"), ConfigPath(child)); err != nil {
		t.Fatal(err)
	}
	if got := FindRoot(child); got != parent {
		t.Errorf("FindRoot = %q, want the parent %q", got, parent)
	}
}

// B-45: the JSONC spellings the file extension promises.
func TestParseConfigAcceptsJSONCNotation(t *testing.T) {
	for name, src := range map[string]string{
		"line comment":         "{\n// c\n\"env\": {\"A\": \"b\"}\n}",
		"block comment":        "{/* c */\"env\": {\"A\": \"b\"}}",
		"trailing comma":       "{\"env\": {\"A\": \"b\",},}",
		"crlf with comments":   "{\r\n// c\r\n\"env\": {\"A\": \"b\"},\r\n}\r\n",
		"comment after value":  "{\"env\": {\"A\": \"b\" // trailing\n}}",
		"block inside object":  "{\"env\": {/* c */\"A\": \"b\"}}",
		"comment before comma": "{\"env\": {\"A\": \"b\"/* c */,}}",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := bParse(src)
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if cfg.Env["A"] != "b" {
				t.Errorf("env = %v, want A=b", cfg.Env)
			}
		})
	}
}

// B-46: this is a file people edit by hand, so a syntax error has to say where.
func TestParseConfigSyntaxErrorsNameFileAndPosition(t *testing.T) {
	for name, src := range map[string]string{
		"unterminated block comment": "{\n\"env\": {}\n/* oops\n",
		"unterminated string":        "{\n\"env\": {\"A\": \"x}\n}\n",
		"extra closing brace":        "{\n\"env\": {}\n}}\n",
		"missing closing brace":      "{\n\"env\": {}\n",
		"unterminated line comment":  "{\"env\": {} // oops",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := bParse(src)
			if err == nil {
				t.Fatal("accepted, want a rejection")
			}
			msg := err.Error()
			if !strings.Contains(msg, bConfigPath) {
				t.Errorf("message does not name the file: %v", err)
			}
			if !strings.Contains(msg, "line ") || !strings.Contains(msg, "column ") {
				t.Errorf("message gives no position: %v", err)
			}
		})
	}
}

// B-47: scope.md keeps the refusal -- stripping a BOM blurs what "this is JSONC"
// means -- but "invalid character" alone is the hardest kind of error to act on,
// because the file looks right on screen. The message has to say BOM.
func TestParseConfigRejectsBOMAndSaysSo(t *testing.T) {
	src := "\ufeff" + `{"env": {"A": "b"}}`
	_, err := bParse(src)
	if err == nil {
		t.Fatal("a leading BOM was accepted")
	}
	if !strings.Contains(err.Error(), bConfigPath) {
		t.Errorf("message does not name the file: %v", err)
	}
	t.Run("names the BOM", func(t *testing.T) {
		if !strings.Contains(strings.ToUpper(err.Error()), "BOM") {
			t.Errorf("message = %v; nothing in it tells the user their editor added a byte order mark", err)
		}
	})
}

// B-48: a top level that is not an object is a mistake, not an empty config.
// Reading `null` as "nothing to do" hides a file the user thinks is live.
func TestParseConfigRejectsNonObjectTopLevel(t *testing.T) {
	for name, src := range map[string]string{
		"array":   `["env"]`,
		"string":  `"env"`,
		"number":  `42`,
		"boolean": `true`,
		"null":    `null`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := bParse(src)
			if err == nil {
				t.Fatalf("a top-level %s was accepted as %+v", name, cfg)
			}
			if !strings.Contains(err.Error(), bConfigPath) {
				t.Errorf("message does not name the file: %v", err)
			}
		})
	}
}

// B-49: scope.md keeps unknown top-level keys silently ignored, so a key added
// later is not a breaking change. The cost is that a typo produces a config that
// trusts and applies cleanly while doing nothing, which is pinned here.
func TestParseConfigIgnoresUnknownTopLevelKeys(t *testing.T) {
	for name, src := range map[string]string{
		"misspelt env":    `{"envs": {"A": "b"}}`,
		"misspelt expand": `{"expend": true, "env": {"A": "b"}}`,
		"entirely new":    `{"future": 1, "env": {"A": "b"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := bParse(src)
			if err != nil {
				t.Fatalf("unknown top-level key rejected: %v", err)
			}
			if name == "misspelt env" {
				if len(cfg.Env) != 0 {
					t.Errorf("env = %v, want empty: the misspelt key is ignored", cfg.Env)
				}
			} else if cfg.Env["A"] != "b" {
				t.Errorf("env = %v, want the real entry to survive", cfg.Env)
			}
			if name == "misspelt expand" && cfg.Expand {
				t.Error("a misspelt expand key turned expansion on")
			}
		})
	}
}

// B-50: declaring a workspace without variables is a legitimate thing to do;
// WORKSPACE_PATH alone is the point of it.
func TestParseConfigAcceptsAbsentEnv(t *testing.T) {
	for name, src := range map[string]string{
		"null env":    `{"env": null}`,
		"missing env": `{}`,
		"empty env":   `{"env": {}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := bParse(src)
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			vars := WorkspaceVars("/ws", cfg)
			want := EnvVar{Key: "WORKSPACE_PATH", Val: "/ws", Literal: true}
			if len(vars) != 1 || vars[0] != want {
				t.Errorf("vars = %v, want exactly %v", vars, want)
			}
		})
	}
}

// B-51: strict is the default, and a value that merely looks true must not turn
// expansion on. `"expand": "true"` is a config the user got wrong, not a yes.
func TestParseConfigExpandFlagTypes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src      string
		accepted bool
		expand   bool
	}{
		{"absent", `{"env": {}}`, true, false},
		{"false", `{"expand": false, "env": {}}`, true, false},
		{"true", `{"expand": true, "env": {}}`, true, true},
		{"string true", `{"expand": "true", "env": {}}`, false, false},
		{"number one", `{"expand": 1, "env": {}}`, false, false},
		{"null", `{"expand": null, "env": {}}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := bParse(tc.src)
			if tc.accepted {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				if cfg.Expand != tc.expand {
					t.Errorf("Expand = %v, want %v", cfg.Expand, tc.expand)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted with Expand = %v", cfg.Expand)
			}
			if !strings.Contains(err.Error(), bConfigPath) {
				t.Errorf("message does not name the file: %v", err)
			}
		})
	}
}

// B-52: what a prompt costs has to stay bounded even for a hostile config that
// fits under the size limit. An error is fine; a stack overflow is not.
func TestParseConfigRejectsDeeplyNestedValueWithoutCrashing(t *testing.T) {
	src := `{"env": {"A": ` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}}`
	if len(src) > maxConfigSize {
		t.Fatalf("the payload is %d bytes, past the size limit; it would be refused for the wrong reason", len(src))
	}
	done := make(chan error, 1)
	go func() {
		_, err := bParse(src)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("20,000 levels of nesting were accepted")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("parsing 20,000 levels of nesting did not finish")
	}
}

// B-53: a config that is large but legal is applied on every prompt, so it has
// to parse in a time a person would not notice.
func TestParseConfigHandlesManyEntriesQuickly(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"env": {`)
	const entries = 10000
	for i := 0; i < entries; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"K_%05d":"%s"`, i, strings.Repeat("v", 80))
	}
	b.WriteString(`}}`)
	src := b.String()
	if len(src) > maxConfigSize {
		t.Fatalf("the payload is %d bytes, past the %d-byte limit", len(src), maxConfigSize)
	}

	start := time.Now()
	cfg, err := bParse(src)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("%d entries rejected: %v", entries, err)
	}
	if len(cfg.Env) != entries {
		t.Fatalf("got %d entries, want %d", len(cfg.Env), entries)
	}
	// Generous next to what a person notices at the prompt, tight enough that a
	// quadratic parse or a per-entry syscall shows up.
	if elapsed > 2*time.Second {
		t.Errorf("parsing %d entries took %v", entries, elapsed)
	}
}

// B-54: hujson.Standardize rewrites the buffer it is given. The grant is taken
// over the bytes handed to parseConfig, so dropping the copy would make the
// recorded fingerprint depend on whether a parse happened first.
func TestFingerprintUnchangedByParsing(t *testing.T) {
	for _, pad := range []int{0, 1, 8000} {
		src := []byte("{\n  // comment\n  \"env\": {\"FOO\": \"" + strings.Repeat("x", pad) + "\"}, // trailing\n}\n")
		before := fingerprintBytes(bConfigPath, src)
		if _, err := parseConfig(bConfigPath, src); err != nil {
			t.Fatal(err)
		}
		if after := fingerprintBytes(bConfigPath, src); after != before {
			t.Errorf("pad %d: fingerprint changed across a parse (%s then %s)", pad, before, after)
		}
	}
}
