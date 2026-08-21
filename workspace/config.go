// Package workspace implements .sallyport.jsonc discovery and environment injection.
package workspace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/tailscale/hujson"
)

// ConfigFileName marks a directory as a workspace root; there is no central
// registry and no fixed parent directory.
const ConfigFileName = ".sallyport.jsonc"

type Config struct {
	// Expand opts a config into shell expansion of its env values; the default
	// is strict mode. See EnvVar.Literal.
	Expand bool              `json:"expand"`
	Env    map[string]string `json:"env"`
}

type EnvVar struct {
	Key string
	Val string
	// Literal marks values applied verbatim with single-quoting, so no shell
	// expansion happens: the automatic WORKSPACE_PATH, and every value of a
	// strict-mode config (the default). Non-literal values are zsh double-quoted
	// source text, emitted only under "expand": true, so $VAR and $(...) expand
	// in the user's shell at apply time. Only trusted configs are ever applied;
	// the trust grant, not quoting, is the security boundary (a trusted config
	// already controls PATH).
	Literal bool
}

// Keys end up unquoted in `export KEY=...` statements that the shell evals,
// so anything outside identifier syntax would be shell injection.
var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// FindRoot returns the nearest ancestor of dir containing .sallyport.jsonc, or "".
// The name must resolve to a regular file, directly or through a symlink (Nix
// and home-manager deploy configs as symlinks into a read-only store); a link to
// a directory or a dangling target does not mark a workspace. Following is safe
// because a config's identity is its logical location, not its target (see
// configIdentity), and nothing is applied without a trust grant.
func FindRoot(dir string) string {
	// A relative start would search from wherever the process happens to be, and
	// the answer would change with it. Callers pass an absolute path; anything
	// else is a mistake worth refusing rather than guessing at.
	if !filepath.IsAbs(dir) {
		return ""
	}
	// Resolved rather than cleaned, so the search climbs the directories the
	// kernel would: a ".." goes up from wherever the component before it really
	// is, which through a symlink is a different tree than cleaning picks. A
	// path too long to resolve is searched as written, since the length is the
	// only thing wrong with it.
	d := filepath.Clean(dir)
	if resolved, err := canonical(dir); err == nil {
		d = resolved
	}
	for {
		switch fi, err := os.Stat(filepath.Join(d, ConfigFileName)); {
		case err == nil && fi.Mode().IsRegular():
			return d
		case errors.Is(err, fs.ErrPermission):
			// A directory that cannot be read may hold a config, and climbing
			// past it would silently apply a different one from further up.
			return ""
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

func ConfigPath(root string) string { return filepath.Join(root, ConfigFileName) }

// maxConfigSize bounds the per-prompt hook cost: a runaway config must fail
// loudly instead of slowing every prompt.
const maxConfigSize = 1 << 20

// openConfigFile is a variable so tests can act inside the window between the
// open and the checks that follow it, which is where anything swapped in behind
// sallyport's back lands.
var openConfigFile = openConfigFileDefault

// O_NONBLOCK so a fifo left where the config was answers instead of holding the
// prompt open forever; readConfigFile rejects the kind either way.
func openConfigFileDefault(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// readConfigFile opens the config once and answers every question from that one
// descriptor: what it is, how large it is, and what it holds. Asking the path
// again between the checks and the read would let the answers describe
// different files.
func readConfigFile(path string) ([]byte, error) {
	f, err := openConfigFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > maxConfigSize {
		return nil, fmt.Errorf("%s: exceeds %d bytes", path, maxConfigSize)
	}
	// One byte past the limit, so a file that grew after the size above was read
	// is refused rather than truncated into something that parses.
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxConfigSize {
		return nil, fmt.Errorf("%s: exceeds %d bytes", path, maxConfigSize)
	}
	return data, nil
}

func LoadConfig(path string) (Config, error) {
	data, err := readConfigFile(path)
	if err != nil {
		return Config{}, err
	}
	return parseConfig(path, data)
}

func parseConfig(path string, data []byte) (Config, error) {
	// hujson.Standardize mutates its input buffer; callers fingerprint the
	// original bytes, so parsing must not touch them.
	data = append([]byte(nil), data...)
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return Config{}, fmt.Errorf("%s: starts with a UTF-8 BOM; save the file without one", path)
	}
	std, err := hujson.Standardize(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	// Decoded a member at a time rather than straight into Config, so that a
	// JSON null is told apart from an absent member: decoding null into a string
	// or a struct leaves the zero value behind and reports nothing, which turns
	// a typo into an empty config that trust happily approves.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(std, &raw); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if raw == nil {
		return Config{}, fmt.Errorf("%s: top level is null, want an object", path)
	}
	var cfg Config
	if v, ok := raw["expand"]; ok {
		if err := json.Unmarshal(v, &cfg.Expand); err != nil {
			return Config{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	env, err := parseEnv(path, raw["env"])
	if err != nil {
		return Config{}, err
	}
	cfg.Env = env
	// Sorted so that a config with more than one bad key names the same one on
	// every run: map order is random, and a message that moves reads as a second
	// problem appearing after the first was fixed.
	keys := make([]string, 0, len(cfg.Env))
	for key := range cfg.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		val := cfg.Env[key]
		if !keyRe.MatchString(key) {
			return Config{}, fmt.Errorf("invalid env key %q in %s", elide(key), path)
		}
		// A NUL survives JSON and the fingerprint but not the command
		// substitution the hook applies the script through, so the value that
		// reaches the shell would differ from the one that was approved.
		if strings.ContainsRune(val, 0) {
			return Config{}, fmt.Errorf("invalid env value for %q in %s: contains a NUL byte", key, path)
		}
		// Only expand mode emits the value verbatim inside double quotes. Strict
		// mode single-quotes it, which carries any content safely, so the check
		// would only reject values that are in fact fine.
		if cfg.Expand {
			if err := validateQuotedValue(key, path, val); err != nil {
				return Config{}, err
			}
		}
	}
	return cfg, nil
}

func parseEnv(path string, raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("%s: env: %w", path, err)
	}
	env := make(map[string]string, len(members))
	for key, v := range members {
		var val string
		if err := json.Unmarshal(v, &val); err != nil {
			return nil, fmt.Errorf("%s: env %q: %w", path, elide(key), err)
		}
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, fmt.Errorf("%s: env %q is null, want a string", path, elide(key))
		}
		env[key] = val
	}
	return env, nil
}

// elide keeps a message readable when the offending key is a wall of bytes: it
// goes to a terminal, and the point is to say which key, not to reproduce it.
func elide(s string) string {
	const max = 64
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("... (%d bytes)", len(s))
}

// validateQuotedValue rejects values that would not survive being emitted as the
// body of a zsh double-quoted string: an unescaped `"` closes the string early
// and a trailing `\` escapes the closing quote. The hook evals the export script
// as a single unit, so one broken line fails the whole eval, state commit
// included, leaving the shell's sallyport state stuck.
func validateQuotedValue(key, path, val string) error {
	for i := 0; i < len(val); i++ {
		switch val[i] {
		case '\\':
			// A backslash escapes the following byte and consumes it; a trailing
			// one would swallow the closing quote instead.
			i++
			if i >= len(val) {
				return fmt.Errorf("invalid env value for %q in %s: ends with a dangling backslash; write \\\\ for a literal backslash", key, path)
			}
		case '"':
			return fmt.Errorf("invalid env value for %q in %s: contains an unescaped double quote; write \\\" for a literal quote", key, path)
		}
	}
	return nil
}

// WorkspaceVars returns the variables to apply for root, in deterministic
// order. WORKSPACE_PATH is always present so prompt integrations work without
// any configuration, but an explicit env entry wins.
func WorkspaceVars(root string, cfg Config) []EnvVar {
	var vars []EnvVar
	if _, ok := cfg.Env["WORKSPACE_PATH"]; !ok {
		vars = append(vars, EnvVar{Key: "WORKSPACE_PATH", Val: root, Literal: true})
	}
	keys := make([]string, 0, len(cfg.Env))
	for k := range cfg.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vars = append(vars, EnvVar{Key: k, Val: cfg.Env[k], Literal: !cfg.Expand})
	}
	return vars
}
