package workspace

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
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
func ZshHook() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`_sallyport_hook() {
  trap -- '' SIGINT
  eval "$("%s" export zsh)"
  trap - SIGINT
  return 0
}
typeset -ag chpwd_functions
if (( ! ${chpwd_functions[(I)_sallyport_hook]} )); then
  chpwd_functions=(_sallyport_hook $chpwd_functions)
fi
_sallyport_hook
`, self), nil
}

// BuildExportScript emits the env diff for pwd. Movement within one workspace
// emits nothing, which keeps the per-cd cost of the hook near zero.
func BuildExportScript(pwd string) (string, error) {
	st := loadState()
	root := FindRoot(pwd)
	if root == st.Root {
		return "", nil
	}

	// An untrusted config is treated as if the workspace did not exist: the
	// previous workspace still gets restored, but nothing is applied.
	if root != "" && !IsTrusted(ConfigPath(root)) {
		fmt.Fprintf(os.Stderr, "sallyport: %s is not trusted; run `sallyport trust` inside it\n", ConfigPath(root))
		root = ""
	}

	var vars []EnvVar
	if root != "" {
		var err error
		vars, err = WorkspaceVars(root)
		if err != nil {
			// Stdout is eval'd by the shell, so the error goes to stderr and
			// the transition is still recorded; failing here instead would
			// re-trigger the error on every cd inside the workspace.
			fmt.Fprintf(os.Stderr, "sallyport: ignoring broken %s in %s: %v\n", ConfigFileName, root, err)
			vars = nil
		}
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
