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

// stateEnvKey is the env var the binary reads its state from. The shell never
// exports it: the hook passes it in for the single invocation that calls the
// binary, so it cannot leak into child processes.
const stateEnvKey = "__SALLYPORT_STATE"

const stateShellVar = "__sallyport_state"

// state carries the pre-workspace values of everything sallyport overwrote, so
// leaving a workspace restores the shell instead of leaking values into it.
// Because the shell variable holding it is not exported, a shell started inside
// a workspace sees no state and takes the environment it inherited as its own
// baseline: each shell restores to the environment it was born into, not to the
// one from before sallyport ever ran.
type state struct {
	Root string `json:"root"`
	// Fingerprint of the config bytes that were applied. Comparing the root alone
	// misses an edit that gets re-trusted between two prompts, since the
	// untrusted intermediate state is never observed.
	Fingerprint string `json:"fingerprint,omitempty"`
	// nil means the variable did not exist before sallyport touched it.
	Saved map[string]*string `json:"saved"`
	// Schema is a hash of this struct's wire layout, stamped by encodeState and
	// checked by decodeState (see stateSchema). It is metadata, not data, so it
	// is excluded from the schema computation itself.
	Schema string `json:"schema,omitempty"`
}

// ZshHook returns the shim for .zshrc. It must never propagate an error: zsh
// stops running subsequent chpwd hooks when one fails, which would break
// unrelated plugins.
//
// stateShellVar is declared non-exported: an exported state would be inherited
// by every child process the workspace starts, defeating the isolation. The
// hook instead passes it to the binary as stateEnvKey through zsh's one-shot
// command-prefix assignment, which is process-local.
//
// The hook runs on precmd as well as chpwd so trust/untrust and config edits
// take effect on the next prompt without a directory change. The precmd variant
// passes -quiet: repeating the "not trusted" warning on every empty Enter would
// drown the prompt.
//
// The shim only registers and never applies immediately: applying while .zshrc
// is still being sourced lets later export lines clobber workspace values, and
// records pre-.zshrc values as the originals to restore.
func ZshHook() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return zshHookFor(self), nil
}

// zshHookFor renders the shim for a given binary path. It is split out from
// ZshHook so tests can pass hostile paths: os.Executable() cannot be
// substituted, and under `go test` it is always a tame path.
//
// The path is single-quoted with zshQuote rather than interpolated between
// double quotes, which would still expand $ and ` in the installed path; and
// through zshQuote rather than bare single quotes, which a path like
// /Users/o'brien/bin would end early. Single quotes are safe even though the
// eval's `$(...)` sits inside double quotes: a command substitution starts a
// fresh quoting context, which is also why the "${...-}" below works.
func zshHookFor(self string) string {
	return fmt.Sprintf(`typeset -g %[1]s
_sallyport_hook() {
  # The SIGINT mask keeps a Ctrl-C from stopping the eval halfway and leaving the
  # environment and the state global inconsistent. localtraps confines it: zsh
  # restores the caller's traps on return, so a user-defined INT trap survives
  # instead of being reset to the default.
  setopt localoptions localtraps
  trap -- '' SIGINT
  # ${...-} guards against setopt nounset, which would abort the hook if some
  # other code unset the state global.
  eval "$(%[2]s="${%[1]s-}" %[3]s export "$@" zsh)"
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
`, stateShellVar, stateEnvKey, zshQuote(self))
}

// ExportResult carries warnings as data rather than writing them to a stream,
// so the CLI decides where they go. An empty Script means no transition was
// needed.
type ExportResult struct {
	Script   string
	Warnings []string
}

// BuildExportScript emits the env diff for pwd; no change emits an empty
// script. quiet suppresses the informational warnings for the per-prompt
// (precmd) calls.
func BuildExportScript(pwd string, quiet bool) (ExportResult, error) {
	var warnings []string

	st, schemaMismatch, err := decodeState(os.Getenv(stateEnvKey))
	if err != nil {
		warnings = append(warnings, corruptStateWarning)
		st = state{}
	} else if schemaMismatch && !quiet {
		// The recovered originals may be misread; they are still used
		// (best-effort). Self-healing: the first transition through encodeState
		// re-stamps the current schema, so the warning stops on its own.
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
			// No grant the store holds can be trusted; treat the workspace as if it
			// did not exist, with the same gating as the untrusted case below.
			if !quiet || root == st.Root {
				warnings = append(warnings, fmt.Sprintf("sallyport: %v; refusing to apply %s", err, ConfigPath(root)))
			}
			root = ""
		case errors.Is(err, ErrUntrusted):
			// The previous workspace still gets restored, but nothing is applied.
			// The warning is forced through quiet when the grant was revoked while
			// this workspace is applied: a silent rollback would confuse the user.
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
			// direnv and sallyport are unaware of each other and would fight over
			// shared variables non-deterministically.
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
		// typeset -g, not export: this eval runs inside _sallyport_hook, so a plain
		// assignment would be scoped to the function, and the state must stay
		// non-exported (see ZshHook).
		stateLine = fmt.Sprintf("typeset -g %s=%s\n", stateShellVar, zshQuote(encoded))
	}

	return ExportResult{Script: renderScript(st.Saved, vars, stateLine), Warnings: warnings}, nil
}

// captureSaved records, for each variable about to be applied, the value that
// leaving the workspace must restore; nil when it is currently unset. The
// recorded original must predate sallyport entirely, which is why a hit in
// st.Saved wins over the live environment.
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

// renderScript emits restores before applies, so a workspace-to-workspace
// switch ends with the new workspace's values for overlapping keys. stateLine
// goes last: if the process dies mid-write, the shell evals a script whose
// state was never committed, and the next evaluation redoes the whole
// idempotent transition.
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
			// Emitted verbatim between double quotes: the value is zsh
			// double-quoted source text and the shell owns its expansion
			// semantics, escapes included (see EnvVar.Literal).
			fmt.Fprintf(&b, "export %s=\"%s\"\n", v.Key, v.Val)
		}
	}

	b.WriteString(stateLine)
	return b.String()
}

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

const corruptStateWarning = "sallyport: " + stateEnvKey + " is corrupted; the pre-workspace environment cannot be restored"

const schemaMismatchWarning = "sallyport: " + stateEnvKey + " was written by a different sallyport version; interpreting best-effort"

// stateSchema is a short hash of the state struct's wire layout. json.Unmarshal
// never errors on a structural mismatch — it drops unknown fields and zero-fills
// missing ones — so a change to the meaning or type of a field would let a new
// binary silently misread state written by an old one. Stamping this hash into
// every state turns that into an explicit best-effort warning.
var stateSchema = func() string {
	sum := sha256.Sum256([]byte(stateSchemaString()))
	return hex.EncodeToString(sum[:])[:12]
}()

// stateSchemaString pairs each data field's JSON name with its normalized Go
// type, sorted so field order (which JSON does not care about) is not mistaken
// for a change. The Schema field itself is metadata and excluded. A golden test
// pins this string so any edit to the state struct forces a compatibility
// decision.
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

// decodeState parses the base64+JSON state blob. The bool reports a schema
// mismatch: the blob decoded, but its schema differs from this binary's (or
// predates the schema field), so the recovered originals may be misread while
// still being usable. The empty string is "no state" (how the hook clears state
// on leave) and never a mismatch.
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
	// Saved keys are emitted bare into `export KEY=` and `unset KEY`, and keyRe
	// only guards the way in (parseConfig). A blob carrying a key sallyport could
	// never have written is not state to restore from, whatever its schema.
	for k := range s.Saved {
		if !keyRe.MatchString(k) {
			return state{}, false, fmt.Errorf("invalid saved key %q", k)
		}
	}
	return s, s.Schema != stateSchema, nil
}

func encodeState(s state) (string, error) {
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
