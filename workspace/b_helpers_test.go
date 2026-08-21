package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// bConfigPath is the path the parse-only cases report themselves at. Nothing
// reads it: parseConfig only carries the name into its messages, so a message
// assertion can look for it without a file existing.
const bConfigPath = "/ws/.sallyport.jsonc"

func bParse(src string) (Config, error) {
	return parseConfig(bConfigPath, []byte(src))
}

// bKeyConfig makes key the sole env entry. The key goes through quoteJSON:
// pasted raw, a key holding a quote or a newline would break the JSON itself and
// the case would pass on a syntax error instead of on key validation.
func bKeyConfig(key string) string {
	return `{"env": {` + quoteJSON(key) + `: "x"}}`
}

func bValConfig(val string, expand bool) string {
	if expand {
		return `{"expand": true, "env": {"FOO": ` + quoteJSON(val) + `}}`
	}
	return `{"env": {"FOO": ` + quoteJSON(val) + `}}`
}

// bWantInvalidKey asserts a key rejection names both halves of what the user has
// to fix: the offending key, quoted so control characters cannot reach the
// terminal raw, and the file it lives in. key is the key as the JSON decoder
// produced it, which is not always the key as written (see B-09).
func bWantInvalidKey(t *testing.T, key string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("key %q accepted, want rejection", key)
		return
	}
	msg := err.Error()
	if !strings.Contains(msg, "invalid env key") {
		t.Errorf("key %q rejected for the wrong reason: %v", key, err)
		return
	}
	if !strings.Contains(msg, strconv.Quote(key)) {
		t.Errorf("key %q: message does not name the key quoted: %v", key, err)
	}
	if !strings.Contains(msg, bConfigPath) {
		t.Errorf("key %q: message does not name the file: %v", key, err)
	}
}

// bRequireNoAncestorConfig fails loudly when any ancestor of dir holds a
// .sallyport.jsonc. FindRoot climbs to the filesystem root, so a config planted
// above the temp directory decides the answer of every search meant to find
// nothing, and the failure would otherwise look like a bug in FindRoot (B-65).
func bRequireNoAncestorConfig(t *testing.T, dir string) {
	t.Helper()
	for d := filepath.Clean(dir); ; {
		if _, err := os.Stat(filepath.Join(d, ConfigFileName)); err == nil {
			t.Fatalf("%s holds a %s; it is an ancestor of the test tree %s, so it would answer searches that must find nothing. Remove it and rerun.", d, ConfigFileName, dir)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return
		}
		d = parent
	}
}

func bZsh(t *testing.T) string {
	t.Helper()
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not available")
	}
	return zsh
}

// bWantZshParses runs the shell's own parser over a rendered script. The hook
// evals the script as one unit, so a single malformed line fails the whole eval,
// state commit included, and leaves the shell's sallyport state stuck.
func bWantZshParses(t *testing.T, zsh, script string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "script.zsh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(zsh, "-n", path).CombinedOutput()
	if err != nil {
		t.Errorf("zsh -n rejected the rendered script: %v\n%s\n--- script ---\n%s", err, out, script)
	}
}

// bIsolatedTree returns a temp directory whose ancestors are known to hold no
// config, for the FindRoot cases whose expected answer depends on that.
func bIsolatedTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bRequireNoAncestorConfig(t, dir)
	return dir
}
