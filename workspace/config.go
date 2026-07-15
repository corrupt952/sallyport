// Package workspace implements .sallyport.jsonc discovery and environment injection.
package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/tailscale/hujson"
)

// ConfigFileName marks a directory as a workspace root; there is no central
// registry and no fixed parent directory.
const ConfigFileName = ".sallyport.jsonc"

type Config struct {
	// Expand opts a config into shell expansion of its env values. Default
	// false is strict mode: values are single-quoted and applied verbatim,
	// which safely carries any content. With "expand": true the values become
	// zsh double-quoted source text so $VAR, $(...) and escapes are handled by
	// the shell at apply time. See EnvVar.Literal.
	Expand bool              `json:"expand"`
	Env    map[string]string `json:"env"`
}

type EnvVar struct {
	Key string
	Val string
	// Literal marks values applied verbatim with single-quoting, so no shell
	// expansion happens: the automatic WORKSPACE_PATH, and every value of a
	// strict-mode config (the default). Non-literal values are zsh
	// double-quoted source text, emitted only when the config sets
	// "expand": true; $VAR and $(...) then expand in the user's shell at apply
	// time, exactly as if the export line were written in .zshrc. Only trusted
	// configs are ever applied; the trust grant, not quoting, is the security
	// boundary (a trusted config already controls PATH).
	Literal bool
}

// Keys end up unquoted in `export KEY=...` statements that the shell evals,
// so anything outside identifier syntax would be shell injection.
var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// FindRoot returns the nearest ancestor of dir containing .sallyport.jsonc, or "".
// The name must resolve to a regular file: either a regular file directly, or a
// symlink to one (Nix and home-manager deploy configs as symlinks into a
// read-only store). Symlinks are followed to regular files only — a link to a
// directory, a device, or a dangling target does not mark a workspace. Following
// is safe because a config's identity is its logical location, not its target
// (see configIdentity), and nothing in a config is ever applied without a trust
// grant, so a hostile link cannot smuggle env vars in.
func FindRoot(dir string) string {
	d := filepath.Clean(dir)
	for {
		if fi, err := os.Stat(filepath.Join(d, ConfigFileName)); err == nil && fi.Mode().IsRegular() {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

func ConfigPath(root string) string { return filepath.Join(root, ConfigFileName) }

// maxConfigSize bounds the per-prompt hook cost: parsing scales linearly with
// file size, so a runaway config must fail loudly instead of slowing every
// prompt. Legitimate configs are a few hundred bytes.
const maxConfigSize = 1 << 20

func readConfigFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxConfigSize {
		return nil, fmt.Errorf("%s: exceeds %d bytes", path, maxConfigSize)
	}
	return os.ReadFile(path)
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
	std, err := hujson.Standardize(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(std, &cfg); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	for key, val := range cfg.Env {
		if !keyRe.MatchString(key) {
			return Config{}, fmt.Errorf("invalid env key %q in %s", key, path)
		}
		// The value check only matters in expand mode, where the value is
		// emitted verbatim inside double quotes and a stray " or trailing \
		// would break the export line. Strict mode single-quotes every value,
		// which safely carries any content, so the check would only reject
		// values that are in fact fine.
		if cfg.Expand {
			if err := validateQuotedValue(key, path, val); err != nil {
				return Config{}, err
			}
		}
	}
	return cfg, nil
}

// validateQuotedValue rejects values that would not survive being emitted as
// the body of a zsh double-quoted string (see EnvVar.Literal and export.go).
// Config values are written verbatim inside `export KEY="..."`, so an
// unescaped `"` closes the string early and a trailing `\` escapes the closing
// quote — either one corrupts that line. Because the hook evals the entire
// export script as a single unit, one broken line fails the whole eval,
// including the state commit, leaving the shell's sallyport state stuck. We
// catch it at parse time so both `sallyport trust` and every load refuse it up
// front instead of breaking the shell later.
func validateQuotedValue(key, path, val string) error {
	for i := 0; i < len(val); i++ {
		switch val[i] {
		case '\\':
			// A backslash escapes the following byte and consumes it; a
			// trailing one has nothing to escape and would swallow the closing
			// quote instead.
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
		// Strict mode (the default) applies values literally with single
		// quotes; expand mode double-quotes them so the shell expands. The
		// automatic WORKSPACE_PATH is always literal (see above).
		vars = append(vars, EnvVar{Key: k, Val: cfg.Env[k], Literal: !cfg.Expand})
	}
	return vars
}
