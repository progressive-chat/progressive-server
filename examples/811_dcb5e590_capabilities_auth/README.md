# Step 811 — "Getting capabilities requires authentication" (Conduit `dcb5e590`)

Source: [`timokoesters/conduit@dcb5e590`](https://github.com/timokoesters/conduit/commit/dcb5e590) (2021-07-11)

Upstream wraps `GET /_matrix/client/r0/capabilities` in `Ruma<...>` so
unauthenticated requests are rejected instead of served.

## What changed vs step 810

| Rust change | C++ translation |
|---|---|
| **`/capabilities` requires authentication** | **Implemented** — the route checks the access token first and returns `401 M_UNKNOWN_TOKEN` without one, like every other authed route in this port |
| **Route body (`m.room_versions`: default v6, v6 stable)** | **Backfilled** — the handler predates this commit upstream but was never translated here; added in the same upstream shape (`default: "6"`, `available: {"6": "stable"}`), matching this port's room creation (`room_version: "6"`) |

Skipped on the way here (per project rules): `fcc30f05` + `36681dd3`
(CI nightly tags), `3fa09ff5` (Cargo thin-lto), `6a96cfaa` (Docker default
port), `09a8737f` (lib re-export + clippy lints), all merges.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit811
# no token -> 401; with token -> 200 + m.room_versions
$ curl -s http://127.0.0.1:8000/_matrix/client/r0/capabilities
{"errcode":"M_UNKNOWN_TOKEN",...}
```
