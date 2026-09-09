# Step 121 — "feat: forward federation errors to the client" (Conduit `e5c71195`)

Source: [`timokoesters/conduit@e5c71195`](https://github.com/timokoesters/conduit/commit/e5c71195) (2021-05-23)

Straight-order intermediate `9b77eb7b` (sync state gating) is a no-op here:
C++ sync rooms carry no state deltas yet, so there is nothing to over-send.

## What changed vs step 120

| Rust change | C++ translation |
|---|---|
| **`Error::FederationError(origin, error)` → "Answer from …"** | **Implemented** — `federation::is_remote_error()` + `remote_error_message()` (`"Answer from <server>: <message>"`); non-200 Matrix errors are logged with origin context in `send_request` (response still returned for the existing errcode checks) |
| **Non-200 → parsed remote error instead of generic failure** | **Implemented** — join candidates keep going past errcode responses; the last remote error is forwarded (live `/join` 502, helper-based route 403); invite failures forward the remote message instead of generic "event not authorized" |
| **Prerequisite fix: split `host:port` for the TLS client** | **Implemented** — `actual_destination` was passed whole as the hostname (unresolvable: `getaddrinfo("h:port")` always fails), so *no* federation send could ever connect; the client now gets a split host + numeric port (IPv6-aware). Without this, no remote error could ever be received to forward |
| **`invite_helper` error propagation** | **Implemented** — helpers now return `optional<string>` error (nullopt = ok); createRoom keeps ignoring per-invite failures |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
