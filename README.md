# sallyport

[![CI](https://github.com/corrupt952/sallyport/actions/workflows/ci.yaml/badge.svg)](https://github.com/corrupt952/sallyport/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/corrupt952/sallyport)](https://goreportcard.com/report/github.com/corrupt952/sallyport)

A trust-based, per-directory shell hook for zsh. `sallyport` applies environment variables declared in a `.sallyport.jsonc` file the moment you `cd` into (or below) the directory that owns it, and restores your previous environment the moment you leave — the same idea as `direnv`, but every config must be explicitly trusted before its contents are ever applied.

## Why sallyport?

Tools that auto-apply directory-local environment variables are convenient, but a `.envrc`-style file is also something a `git clone` can hand you unreviewed. `sallyport` treats that as the primary threat model:

- **Nothing applies until you `trust` it.** A grant is `sha256(config identity + content)`; editing a trusted config silently revokes the grant, so a malicious edit after review can never ride on an old approval.
- **The trust store itself is verified.** Before honoring any grant, sallyport checks that its trust directory is owned by you and not writable by anyone else — an insecure store means every grant it holds could be forged.
- **Nix/home-manager symlinked configs are handled correctly.** A config deployed as a symlink into a read-only store is identified by where it sits, not by its target, so a store-path change across a rebuild keeps the same trust grant while an edit to the underlying bytes still revokes it.
- **Your previous environment always comes back.** Leaving a workspace restores exactly what was there before, including variables that didn't exist (which get `unset`, not left empty).

## Installation

### Nix

```sh
# Run without installing (builds current main)
nix run github:corrupt952/sallyport -- --help

# Install into your profile
nix profile install github:corrupt952/sallyport

# Pin to a release tag or any commit
nix profile install github:corrupt952/sallyport/v0.1.0
```

Builds from source; `sallyport version` reports the commit hash the build came from.

### Download binary

Download the latest binary from [GitHub Releases](https://github.com/corrupt952/sallyport/releases).

### go install

```sh
go install github.com/corrupt952/sallyport@latest
```

### Build from source

```sh
git clone https://github.com/corrupt952/sallyport.git
cd sallyport
make build
```

## Quick Start

Add the hook to your `.zshrc`:

```sh
eval "$(sallyport hook zsh)"
```

Then, inside any directory you want workspace-scoped environment variables for:

```sh
cd my-project
sallyport create   # writes .sallyport.jsonc and trusts it
```

Edit `.sallyport.jsonc`:

```jsonc
{
  // Environment variables applied while inside this workspace.
  // WORKSPACE_PATH is exported automatically.
  // Set "expand": true to let zsh expand $VAR etc. in values.
  "env": {
    "OP_ACCOUNT": "acct.example.com"
  },
}
```

Re-trust after editing (a fresh edit is untrusted until reviewed again):

```sh
sallyport trust
```

`cd` into the directory (or any subdirectory) and the variables apply automatically on your next prompt; `cd` back out and they're gone.

## Commands

| Command | Description |
| --- | --- |
| `sallyport create` | Write a `.sallyport.jsonc` template in the current directory and trust it |
| `sallyport hook zsh` | Print the zsh integration shim (used in `.zshrc`) |
| `sallyport export zsh` | Print the env diff for the current directory (invoked by the hook, not usually run by hand) |
| `sallyport trust` | Approve the nearest `.sallyport.jsonc` so its env gets applied |
| `sallyport untrust` | Revoke approval of the nearest `.sallyport.jsonc` |
| `sallyport prune` | Remove trust records whose config file no longer exists |
| `sallyport version` | Print the sallyport version |

Run `sallyport help` for the full built-in usage.

## Config format (`.sallyport.jsonc`)

`.sallyport.jsonc` is JSON with comments and trailing commas ([HuJSON](https://github.com/tailscale/hujson)):

```jsonc
{
  "expand": false,
  "env": {
    "KEY": "value"
  },
}
```

- `env` — a map of environment variables to apply while inside the directory. `WORKSPACE_PATH` (the workspace root) is always exported automatically unless you set it explicitly.
- `expand` (default `false`, strict mode) — values are applied verbatim via single-quoting; safe for any content, no shell expansion. Set to `true` to have zsh expand `$VAR`, `$(...)`, etc. in values at apply time.

A workspace is any directory whose nearest ancestor (searching upward) has a `.sallyport.jsonc`; every directory below it inherits the same environment until you leave that subtree.

## Development

```sh
make test    # go test -race -count=1 ./...
make lint    # golangci-lint run
make build   # go build -ldflags "-X .../command.Version=..." -o sallyport .
make run     # go run . <args>
```

A Nix devShell (`nix develop`) provides `go`, `gopls`, `gotools`, `golangci-lint`, and `goreleaser`.

Releases are cut by pushing a tag; [`.github/workflows/release.yaml`](.github/workflows/release.yaml) runs [GoReleaser](https://goreleaser.com) to build and publish binaries.

## License

MIT License - see [LICENSE](LICENSE) for details.
