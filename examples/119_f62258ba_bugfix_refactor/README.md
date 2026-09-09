# Step 119 — "improvement: bug fixes and refactors" (Conduit `f62258ba`)

Source: [`timokoesters/conduit@f62258ba`](https://github.com/timokoesters/conduit/commit/f62258ba) (2021-05-12)

Straight-order intermediates with no C++ behavior change: `a0457000` /
`5be5c9e9` (Cargo-only ruma bumps), `af6fea3d` / `2e1d7d12`
(`CanonicalJsonValue` constructor churn — no ruma types in C++),
`3408d74f` (trusted_servers config/docs only), `c2b72773` (clippy).

## What changed vs step 118

| Rust change | C++ translation |
|---|---|
| **`power_level_content_override` merges into defaults** | **Implemented** — new `CreateRoomRequest.power_level_content_override` (parsed from body); unknown keys overlay the default PL content instead of replacing it |
| **Warn (not silent skip) on unverifiable send_join PDUs** | **Implemented** — failed `pdu_append` in the send_join response loop logs `[warn] PDU could not be verified: <event_id>` |
| **Log every error response (`error.rs` warn)** | **Implemented** — central `respond_result` logs `[warn] <status>: <message>` |
| **EDU/sending refactor, presence clear on restart, tree rename** | **Documented** — no sending queue / presence / EDU code in C++ yet |
| **Read-receipt sync shape + incoming receipts** | **Documented** — no receipt endpoints in C++ yet |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
