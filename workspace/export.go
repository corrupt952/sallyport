package workspace

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// stateEnvKey carries the pre-workspace values of everything sallyport overwrote,
// so leaving a workspace restores the shell instead of leaking values into it.
const stateEnvKey = "__SALLYPORT_STATE"

type state struct {
	Root string `json:"root"`
	// nil means the variable did not exist before sallyport touched it.
	Saved map[string]*string `json:"saved"`
}

// ZshHook returns the shim for .zshrc. All logic stays in the binary; the
// shim only evals `sallyport export zsh` output. It must never propagate an error:
// zsh stops running subsequent chpwd hooks when one fails, which would break
// unrelated plugins. SIGINT is masked around the eval so a Ctrl-C cannot stop
// it halfway and leave the environment and __SALLYPORT_STATE inconsistent.
//
// The hook runs on precmd as well as chpwd so that trust/untrust and config
// edits take effect on the next prompt without a directory change (the same
// reason direnv hooks both). The precmd variant passes -quiet: repeating the
// "not trusted" warning on every empty Enter would drown the prompt.
//
// The shim only registers and never applies immediately: applying while
// .zshrc is still being sourced lets later export lines clobber workspace
// values (frozen in by the fast path), and records pre-.zshrc values as the
// originals to restore. Deferring to the first precmd, as direnv does, makes
// the .zshrc order irrelevant.
func ZshHook() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`_sallyport_hook() {
  trap -- '' SIGINT
  eval "$("%s" export "$@" zsh)"
  trap - SIGINT
  return 0
}
_sallyport_hook_precmd() {
  _sallyport_hook -quiet
}
typeset -ag chpwd_functions precmd_functions
if (( ! ${chpwd_functions[(I)_sallyport_hook]} )); then
  chpwd_functions=(_sallyport_hook $chpwd_functions)
fi
if (( ! ${precmd_functions[(I)_sallyport_hook_precmd]} )); then
  precmd_functions=(_sallyport_hook_precmd $precmd_functions)
fi
`, self), nil
}

// BuildExportScript emits the env diff for pwd; no change emits nothing.
// quiet suppresses the untrusted warning for the per-prompt (precmd) calls.
func BuildExportScript(pwd string, quiet bool) (string, error) {
	st := loadState()
	// zsh exports the logical $PWD, so entering through a symlink would
	// otherwise record a state root that never matches the canonical one.
	if c, err := canonical(pwd); err == nil {
		pwd = c
	}
	root := FindRoot(pwd)

	var vars []EnvVar
	if root != "" {
		switch cfg, err := LoadTrustedConfig(ConfigPath(root)); {
		case errors.Is(err, ErrUntrusted):
			// Treated as if the workspace did not exist: the previous
			// workspace still gets restored, but nothing is applied. The
			// warning is forced through quiet when the grant was revoked
			// while the workspace is applied — a silent rollback of the
			// user's environment would be confusing.
			if !quiet || root == st.Root {
				fmt.Fprintf(os.Stderr, "sallyport: %s is not trusted; run `sallyport trust` inside it\n", ConfigPath(root))
			}
			root = ""
		case err != nil:
			// Stdout is eval'd by the shell, so the error goes to stderr and
			// the transition is still recorded; failing here instead would
			// re-trigger the error on every cd inside the workspace.
			if !quiet {
				fmt.Fprintf(os.Stderr, "sallyport: ignoring broken %s in %s: %v\n", ConfigFileName, root, err)
			}
		default:
			vars = WorkspaceVars(root, cfg)
			// direnv and sallyport are unaware of each other and would fight
			// over shared variables non-deterministically; make coexistence
			// visible instead of mysterious.
			if envrc := findDirenvFile(root); envrc != "" && !quiet {
				fmt.Fprintf(os.Stderr, "sallyport: %s is also managed by direnv (%s); shared variables will conflict\n", root, envrc)
			}
		}
	}

	// The comparison runs after trust filtering, not before: revocation and
	// expiry must take effect on the next prompt even without a cd.
	if root == st.Root {
		return "", nil
	}

	var b strings.Builder

	// Restores are emitted before applies so a workspace-to-workspace switch
	// ends with the new workspace's values for overlapping keys.
	restoreKeys := make([]string, 0, len(st.Saved))
	for k := range st.Saved {
		restoreKeys = append(restoreKeys, k)
	}
	sort.Strings(restoreKeys)
	for _, k := range restoreKeys {
		if old := st.Saved[k]; old != nil {
			fmt.Fprintf(&b, "export %s=%s\n", k, zshQuote(*old))
		} else {
			fmt.Fprintf(&b, "unset %s\n", k)
		}
	}

	newSaved := map[string]*string{}
	for _, v := range vars {
		// The recorded original must predate sallyport entirely; when switching
		// between workspaces the previous state already holds it.
		if orig, hit := st.Saved[v.Key]; hit {
			newSaved[v.Key] = orig
		} else if cur, exists := os.LookupEnv(v.Key); exists {
			c := cur
			newSaved[v.Key] = &c
		} else {
			newSaved[v.Key] = nil
		}
		fmt.Fprintf(&b, "export %s=%s\n", v.Key, zshQuote(v.Val))
	}

	if root == "" {
		fmt.Fprintf(&b, "unset %s\n", stateEnvKey)
	} else {
		encoded, err := encodeState(state{Root: root, Saved: newSaved})
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "export %s=%s\n", stateEnvKey, zshQuote(encoded))
	}
	return b.String(), nil
}

// findDirenvFile returns the nearest .envrc at root or above, or "".
func findDirenvFile(dir string) string {
	d := filepath.Clean(dir)
	for {
		p := filepath.Join(d, ".envrc")
		if _, err := os.Lstat(p); err == nil {
			return p
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

func loadState() state {
	raw := os.Getenv(stateEnvKey)
	if raw == "" {
		return state{}
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		warnCorruptState()
		return state{}
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		warnCorruptState()
		return state{}
	}
	return s
}

// Corruption is not silently absorbed: the saved originals are gone, so the
// user must know their pre-workspace environment can no longer be restored.
func warnCorruptState() {
	fmt.Fprintf(os.Stderr, "sallyport: %s is corrupted; the pre-workspace environment cannot be restored\n", stateEnvKey)
}

func encodeState(s state) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func zshQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
