package workspace

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// stateEnvKey is the environment variable the binary reads its state from
// (decodeState). The shell never exports it: it keeps the encoded value in
// stateShellVar, a non-exported global, and the hook passes it in as this
// env var only for the single invocation that calls the binary. Nothing
// else ever sees it, so it cannot leak into child processes.
const stateEnvKey = "__SALLYPORT_STATE"

// stateShellVar is the non-exported zsh global the hook stores the encoded
// state in between invocations.
const stateShellVar = "__sallyport_state"

// state carries the pre-workspace values of everything sallyport overwrote,
// so leaving a workspace restores the shell instead of leaking values into
// it. Because it lives in a non-exported shell variable, a shell started
// inside a workspace does not inherit its parent's state: that child's
// first hook invocation sees no state and records the workspace-applied
// environment it inherited as its own baseline. So each shell restores to
// the environment it was born into, not necessarily the environment from
// before sallyport ever ran.
type state struct {
	Root string `json:"root"`
	// Fingerprint of the config bytes that were applied. Comparing the root
	// alone misses an edit that gets re-trusted between two prompts: the
	// untrusted intermediate state is never observed, so without this the old
	// values would stay applied until the workspace is left.
	Fingerprint string `json:"fingerprint,omitempty"`
	// nil means the variable did not exist before sallyport touched it.
	Saved map[string]*string `json:"saved"`
	// Schema is a hash of this struct's wire layout, stamped by encodeState and
	// checked by decodeState. It lets a new binary notice that a running shell's
	// state was written by a different sallyport version (see stateSchema). It
	// is metadata, not data, so it is excluded from the schema computation
	// itself.
	Schema string `json:"schema,omitempty"`
}

// ZshHook returns the shim for .zshrc. All logic stays in the binary; the
// shim only evals `sallyport export zsh` output. It must never propagate an error:
// zsh stops running subsequent chpwd hooks when one fails, which would break
// unrelated plugins. SIGINT is masked around the eval so a Ctrl-C cannot stop
// it halfway and leave the environment and stateShellVar inconsistent; the
// mask is confined with `localtraps` so a user-defined INT trap is restored on
// return instead of being reset to the default.
//
// stateShellVar is declared with `typeset -g` (non-exported) rather than
// exported: an exported state would be inherited by every child process the
// workspace starts, defeating the point of an isolated workspace. The hook
// instead passes it to the binary as stateEnvKey for the duration of a
// single invocation, using zsh's one-shot command-prefix assignment; that
// assignment is process-local and never touches the shell's own
// environment or its other children.
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
	return fmt.Sprintf(`typeset -g %[1]s
_sallyport_hook() {
  # localoptions/localtraps confine both the SIGINT mask and any option change
  # to this function: zsh restores the caller's traps on return, so a
  # user-defined INT trap survives instead of being reset to the default. The
  # mask still guarantees a Ctrl-C cannot stop the eval halfway and leave the
  # environment and stateShellVar inconsistent.
  setopt localoptions localtraps
  trap -- '' SIGINT
  # ${...-} guards against setopt nounset: after a workspace is left the state
  # global is set to '' (not unset), but a defensive default keeps the hook
  # working even if some other code unset it.
  eval "$(%[2]s="${%[1]s-}" "%[3]s" export "$@" zsh)"
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
`, stateShellVar, stateEnvKey, self), nil
}

// ExportResult is the outcome of evaluating a directory: the shell script to
// eval and any human-facing warnings. Warnings are returned as data, not
// written to a stream, so the CLI decides where they go (stderr) and tests can
// assert on them directly without capturing output. An empty Script means no
// transition was needed.
type ExportResult struct {
	Script   string
	Warnings []string
}

// BuildExportScript emits the env diff for pwd; no change emits an empty
// script. quiet suppresses the informational warnings for the per-prompt
// (precmd) calls. It reads the state from the environment and the config from
// disk, but performs no output of its own: the script and warnings come back
// as data.
func BuildExportScript(pwd string, quiet bool) (ExportResult, error) {
	var warnings []string

	st, schemaMismatch, err := decodeState(os.Getenv(stateEnvKey))
	if err != nil {
		// Corruption is not silently absorbed: the saved originals are gone, so
		// the user must know their pre-workspace environment can no longer be
		// restored.
		warnings = append(warnings, corruptStateWarning)
		st = state{}
	} else if schemaMismatch && !quiet {
		// The state decoded but came from a different state layout; the recovered
		// originals may be misread. We keep using them (best-effort), but say so.
		// Gated on !quiet like the other prompt warnings, and self-healing: the
		// first transition through encodeState re-stamps the current schema, so
		// the warning stops on its own.
		warnings = append(warnings, schemaMismatchWarning)
	}

	// zsh exports the logical $PWD, so entering through a symlink would
	// otherwise record a state root that never matches the canonical one.
	if c, err := canonical(pwd); err == nil {
		pwd = c
	}
	root := FindRoot(pwd)

	var vars []EnvVar
	var fp string
	if root != "" {
		switch cfg, loadedFP, err := LoadTrustedConfig(ConfigPath(root)); {
		case errors.Is(err, ErrUnsafeTrustStore):
			// The store itself is tampering-exposed, so no grant it holds can be
			// trusted; treat the workspace as if it did not exist. Same rollback
			// and warning gating as the untrusted case: a silent rollback of an
			// applied workspace would confuse the user.
			if !quiet || root == st.Root {
				warnings = append(warnings, fmt.Sprintf("sallyport: %v; refusing to apply %s", err, ConfigPath(root)))
			}
			root = ""
		case errors.Is(err, ErrUntrusted):
			// Treated as if the workspace did not exist: the previous
			// workspace still gets restored, but nothing is applied. The
			// warning is forced through quiet when the grant was revoked
			// while the workspace is applied — a silent rollback of the
			// user's environment would be confusing.
			if !quiet || root == st.Root {
				warnings = append(warnings, fmt.Sprintf("sallyport: %s is not trusted; run `sallyport trust` inside it", ConfigPath(root)))
			}
			root = ""
		case err != nil:
			// The transition is still recorded so the hook does not re-trigger
			// the error on every cd inside the workspace.
			if !quiet {
				warnings = append(warnings, fmt.Sprintf("sallyport: ignoring broken %s in %s: %v", ConfigFileName, root, err))
			}
		default:
			vars = WorkspaceVars(root, cfg)
			fp = loadedFP
			// direnv and sallyport are unaware of each other and would fight
			// over shared variables non-deterministically; make coexistence
			// visible instead of mysterious.
			if envrc := findDirenvFile(root); envrc != "" && !quiet {
				warnings = append(warnings, fmt.Sprintf("sallyport: %s is also managed by direnv (%s); shared variables will conflict", root, envrc))
			}
		}
	}

	// The comparison runs after trust filtering, not before: revocation and
	// expiry must take effect on the next prompt even without a cd. The
	// fingerprint participates so an edited-and-retrusted config reapplies
	// even though the root never changed.
	if root == st.Root && fp == st.Fingerprint {
		return ExportResult{Warnings: warnings}, nil
	}

	stateLine := fmt.Sprintf("typeset -g %s=''\n", stateShellVar)
	if root != "" {
		encoded, err := encodeState(state{Root: root, Fingerprint: fp, Saved: captureSaved(st, vars)})
		if err != nil {
			return ExportResult{}, err
		}
		// typeset -g, not export: this eval runs inside _sallyport_hook, so a
		// plain assignment would be scoped to the function. The state itself
		// must stay non-exported (see stateShellVar).
		stateLine = fmt.Sprintf("typeset -g %s=%s\n", stateShellVar, zshQuote(encoded))
	}

	return ExportResult{Script: renderScript(st.Saved, vars, stateLine), Warnings: warnings}, nil
}

// captureSaved records, for each variable about to be applied, the value that
// leaving the workspace must restore: the pre-sallyport original (already held
// in st when switching workspaces) or the current environment value, or nil
// when the variable is currently unset. The recorded original must predate
// sallyport entirely, which is why a hit in st.Saved wins over the live env.
func captureSaved(st state, vars []EnvVar) map[string]*string {
	saved := map[string]*string{}
	for _, v := range vars {
		if orig, hit := st.Saved[v.Key]; hit {
			saved[v.Key] = orig
		} else if cur, exists := os.LookupEnv(v.Key); exists {
			c := cur
			saved[v.Key] = &c
		} else {
			saved[v.Key] = nil
		}
	}
	return saved
}

// renderScript is pure: given the originals to restore, the variables to apply,
// and the pre-built state-commit line, it always produces the same bytes.
// Restores are emitted before applies so a workspace-to-workspace switch ends
// with the new workspace's values for overlapping keys. stateLine is emitted
// last: if the process dies mid-write, the shell evals a script whose state was
// never committed, and the next evaluation redoes the whole idempotent
// transition.
func renderScript(saved map[string]*string, vars []EnvVar, stateLine string) string {
	var b strings.Builder

	restoreKeys := make([]string, 0, len(saved))
	for k := range saved {
		restoreKeys = append(restoreKeys, k)
	}
	sort.Strings(restoreKeys)
	for _, k := range restoreKeys {
		if old := saved[k]; old != nil {
			fmt.Fprintf(&b, "export %s=%s\n", k, zshQuote(*old))
		} else {
			fmt.Fprintf(&b, "unset %s\n", k)
		}
	}

	for _, v := range vars {
		if v.Literal {
			fmt.Fprintf(&b, "export %s=%s\n", v.Key, zshQuote(v.Val))
		} else {
			// Config values are emitted verbatim between double quotes: the
			// value is zsh double-quoted source text and the shell owns its
			// expansion semantics, escapes included (see EnvVar.Literal).
			fmt.Fprintf(&b, "export %s=\"%s\"\n", v.Key, v.Val)
		}
	}

	b.WriteString(stateLine)
	return b.String()
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

// corruptStateWarning is surfaced when the encoded state cannot be decoded.
const corruptStateWarning = "sallyport: " + stateEnvKey + " is corrupted; the pre-workspace environment cannot be restored"

// schemaMismatchWarning is surfaced when a decoded state's schema does not
// match this binary's. It self-heals: the next transition re-encodes the state
// with the current schema, so the warning stops appearing after that.
const schemaMismatchWarning = "sallyport: " + stateEnvKey + " was written by a different sallyport version; interpreting best-effort"

// stateSchema is a short hash of the state struct's wire layout, computed once
// at startup. json.Unmarshal never errors on a structural mismatch — it drops
// unknown fields and zero-fills missing ones — so a change to the meaning or
// type of a field would let a new binary silently misread state written by an
// old one (the class of bug that bit shadowenv across 2.x->3.x). Stamping this
// hash into every state and checking it on decode turns that silent
// misinterpretation into an explicit best-effort warning.
var stateSchema = func() string {
	sum := sha256.Sum256([]byte(stateSchemaString()))
	return hex.EncodeToString(sum[:])[:12]
}()

// stateSchemaString is the canonical description of the state wire layout: each
// data field's JSON name paired with its normalized Go type, sorted so field
// order (which JSON does not care about) is not mistaken for a change. The
// Schema field itself is metadata and excluded. A golden test pins this string
// so any edit to the state struct forces a compatibility decision.
func stateSchemaString() string {
	t := reflect.TypeOf(state{})
	parts := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "schema" {
			continue
		}
		parts = append(parts, name+":"+f.Type.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// decodeState parses the base64+JSON state blob. It is pure. The bool reports a
// schema mismatch: the blob decoded, but its schema differs from this binary's
// (or predates the schema field entirely), so the recovered originals may be
// misread. The caller still uses the decoded state — Go ignores unknown fields
// and zero-fills missing ones, so a wire-compatible change survives — but should
// warn. The empty string is "no state" (also how the hook clears state on
// leave) and never a mismatch; a genuine decode failure is returned as an error.
func decodeState(raw string) (state, bool, error) {
	if raw == "" {
		return state{}, false, nil
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return state{}, false, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return state{}, false, err
	}
	return s, s.Schema != stateSchema, nil
}

func encodeState(s state) (string, error) {
	// Stamp the current schema so a future binary can tell whether this state
	// matches its own layout (see stateSchema).
	s.Schema = stateSchema
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func zshQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
