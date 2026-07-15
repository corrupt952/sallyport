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
	Env map[string]string `json:"env"`
}

type EnvVar struct {
	Key string
	Val string
	// Literal marks values that are actual strings (the automatic
	// WORKSPACE_PATH) and must be applied verbatim. Non-literal values are
	// zsh double-quoted source text: $VAR and $(...) expand in the user's
	// shell at apply time, exactly as if the export line were written in
	// .zshrc. Only trusted configs are ever applied; the trust grant, not
	// quoting, is the security boundary (a trusted config already controls
	// PATH).
	Literal bool
}

// Keys end up unquoted in `export KEY=...` statements that the shell evals,
// so anything outside identifier syntax would be shell injection.
var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// FindRoot returns the nearest ancestor of dir containing .sallyport.jsonc, or "".
// Only a regular file counts: a symlinked .sallyport.jsonc inside an untrusted
// checkout could point at an arbitrary file (a private key, say) and sallyport must
// not follow it.
func FindRoot(dir string) string {
	d := filepath.Clean(dir)
	for {
		if fi, err := os.Lstat(filepath.Join(d, ConfigFileName)); err == nil && fi.Mode().IsRegular() {
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
	for key := range cfg.Env {
		if !keyRe.MatchString(key) {
			return Config{}, fmt.Errorf("invalid env key %q in %s", key, path)
		}
	}
	return cfg, nil
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
		vars = append(vars, EnvVar{Key: k, Val: cfg.Env[k]})
	}
	return vars
}
