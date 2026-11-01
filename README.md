# Dynv Go SDK

Live, restart-free reads of a process's Dynv environment, in Go. One API, three modes:

- **agent** (preferred): under `dynv run`, the client reads the local agent (`DYNV_AGENT_URL`, `DYNV_AGENT_KEY`). It holds no Dynv token and does no crypto.
- **direct**: with a process token and no `dynv` binary, the client fetches `/v1/self` and decrypts and verifies it in-process, exactly as `dynv run` does ([protocol](https://dynv.dev/docs/api/)): signatures, rollback floors, shared groups, templates, watch, and a ciphertext-only cache.
- **env**: neither configured. `Get` reads the process environment and no events fire, so the same code runs in local development.

Standard library only, plus `golang.org/x/crypto/hkdf`. Go 1.22 or newer.

## Install

```sh
go get github.com/hoot-codes/dynv-go
```

## Quick start

```go
import dynv "github.com/hoot-codes/dynv-go"

d, err := dynv.Connect(ctx, dynv.Options{Process: "web"})
if err != nil {
	log.Fatal(err)
}
defer d.Close()

proxy := d.Get("PROXY_SERVER")           // "" when unset
dsn, err := d.Require("DATABASE_URL")    // error naming the key when unset

d.OnKey("PROXY_SERVER", func(v string, ok bool) { rebuildProxy(v, ok) })
d.OnChange(func(e dynv.ChangeEvent) {
	log.Printf("dynv v%d changed %v (restart: %v)", e.Version, e.Changed, e.Restart)
})
```

**Agent mode:** start the app with `dynv run -- ./app`. `Connect` sees `DYNV_AGENT_URL` and reads the agent. A change to a restart-mode variable restarts the app (the supervisor does it).

**Direct mode:** give the app a process token and, ideally, a cache file:

```sh
DYNV_TOKEN_FILE=/run/secrets/dynv DYNV_PROCESS=web DYNV_CACHE=/var/cache/web.dynv ./app
```

A restart-mode change sets `ChangeEvent.Restart`; set `ExitOnRestart` to have the client SIGTERM the process so its orchestrator restarts it.

## Rollover values

`All(key)` returns the current value followed by live fallback values, newest first (an empty slice when unset). Use it to configure libraries that accept older secrets during rotation:

```go
secrets := d.All("AUTH_SECRET") // current secret, then older live secrets
```

### The direct-mode tradeoff

In direct mode **the app holds the token**. Anything that can read its memory or environment (a dependency that dumps env, an error reporter, a debugger, a child process) can take it and keep fetching and decrypting this service's variables until you revoke it. Under `dynv run` the token stays with the supervisor and the app only sees a loopback agent key. So: prefer `dynv run`; in direct mode use one token per deployment, prefer `DYNV_TOKEN_FILE` to `DYNV_TOKEN`, and let the client unset `DYNV_TOKEN` after reading it (the default). Master tokens (`dynv_mt_…`) are refused. See PROTOCOL.md §1.

## API

| | |
|---|---|
| `Connect(ctx, Options) (*Client, error)` | picks the mode, loads the first snapshot, starts watching |
| `Get(key) string`, `Lookup(key) (string, bool)`, `Require(key) (string, error)` | current value. A key Dynv has managed (a value or a tombstone) without a value reads as unset, never as the inherited env |
| `Source(key) string` | the shared group that provides `key` ("" otherwise) |
| `IsTemplate(key) bool`, `Unresolved() []string` | templates (`${NAME}` references) and those that don't resolve right now |
| `Mode()`, `Version()`, `Snapshot()` | `Version` is a local revision: `max(rev+1, doc.version)` per applied change |
| `OnChange(fn)`, `OnKey(key, fn)`, `OnError(fn)` | each returns a cancel func. None fire for the first snapshot. Callbacks run on the watcher goroutine; a panic is recovered and logged |
| `Close() error` | stops watching |

Errors: `*RefusedError{Code}` (`malformed_id`, `envelope`, `gen_mismatch`, `blob`, `process_name`, `rollback`, `fork`) and `*HTTPError{Status}`. The client never takes the app down on a refused or failed update: it keeps the last good environment and retries with backoff.

The protocol layer is exported too (`Verifier`, `ParseToken`, `AEADOpen`, `BlobHash`, `SVFingerprint`, `ParseTemplate`, `Resolve`, `ParseJSON`, …) for tests and other tools.

## Process environment mirroring

By default, the **first snapshot** mirrors every value into the process environment with `os.Setenv`, and unsets every managed key without a value (including restart-mode and dangerous keys). After that, only changes to **hot-mode, non-dangerous** keys are set or unset. Restart-mode keys and dangerous keys (see `IsDangerousKey`: variables that control startup or code loading) keep their existing process-env values until a restart. `Get`, `Lookup`, snapshots, and change events still reflect every live update.

Set `DisableEnvMirror: true` to disable all environment writes. **Use this option with cgo:** calling `os.Setenv` while C code calls `getenv` or `setenv` is a data race in libc, and C libraries may cache environment values instead of observing updates.

## Options

| Field | Default | |
|---|---|---|
| `Mode` | `"auto"` | agent if `DYNV_AGENT_URL` is set, else direct if a token is set, else env. Or `"agent"`, `"direct"`, `"env"` |
| `Token` | `DYNV_TOKEN`, else the trimmed contents of `DYNV_TOKEN_FILE` | a process token (`dynv_pt_…`) |
| `Process` | `DYNV_PROCESS` | expected process name; anything else is refused. Recommended |
| `URL` | `DYNV_URL`; **required** in direct mode (`https://api.dynv.dev` for Dynv Cloud) | https only; http only to loopback or with `AllowInsecureHTTP`. No credentials, query or fragment |
| `Cache` | `DYNV_CACHE` | ciphertext-only cache (`dynv run --cache` format): offline boot and a durable rollback floor. Recommended |
| `Require` | false | fail `Connect` when Dynv is unreachable and there is no cache |
| `BootTimeout` | 10s | first live fetch; after it, the client boots on the cache (`using cached v<N>`) |
| `PollInterval` | 120s | longest error backoff, and the poll interval with `DisableLongPoll` |
| `DisableLongPoll` | false | poll `GET /v1/self` instead of long-polling, for networks that kill idle connections |
| `AllowInsecureHTTP` | `DYNV_ALLOW_INSECURE_HTTP=1` | plain http to a trusted private network |
| `KeepTokenInEnv` | false | by default `DYNV_TOKEN` is unset once read |
| `ExitOnRestart` | false | direct mode: SIGTERM self when a restart-mode variable changes |
| `DisableEnvMirror` | false | disable all process-env writes; by default the first snapshot mirrors everything, later snapshots only hot, non-dangerous keys (see above) |
| `Logger` | stderr, `dynv: ` prefix | diagnostics: key names and codes only, never values |
| `OnError` | none | like `Client.OnError`, but also sees errors during `Connect` (e.g. a refused live response) |
| `AgentURL`, `AgentKey` | `DYNV_AGENT_URL`, `DYNV_AGENT_KEY` | |
| `HTTPClient` | a default client | used for every request; redirects are never followed regardless |

## Development

The system `go` on some machines is gccgo 1.18, which is too old. Use an official toolchain, e.g. the pinned one in `~/.local/go-1.27.3`:

```sh
# install (once): download go1.27.3.linux-amd64.tar.gz from https://go.dev/dl/, check its sha256, then
mkdir -p ~/.local/go-1.27.3 && tar -C ~/.local/go-1.27.3 --strip-components=1 -xzf go1.27.3.linux-amd64.tar.gz
export PATH=$HOME/.local/go-1.27.3/bin:$PATH
GOBIN=$HOME/.local/go-1.27.3/bin go install honnef.co/go/tools/cmd/staticcheck@latest
```

Run the checks (gofmt, vet, staticcheck, `go test -race`, builds):

```sh
scripts/check.sh
```

The tests run every conformance vector in `testdata/` (`protocol-vectors.json`: all primitives and every `self` case, step by step; `template-vectors.json`: parse and resolve), plus unit tests against fake API and agent servers. `DYNV_VECTOR_COUNTS=1 go test .` prints the vector counts.

`e2e/app` is the status app the end-to-end tests drive: it serves its view of the environment as JSON on `127.0.0.1:$APP_PORT`.
