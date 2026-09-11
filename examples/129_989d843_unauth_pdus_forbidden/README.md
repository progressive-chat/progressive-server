# Step 129 — "fix: unauthorized pdus will be responded to with FORBIDDEN" (Conduit `989d843`)

Source: [`timokoesters/conduit@989d843`](https://github.com/timokoesters/conduit/commit/989d843) (2021-05-21)

Upstream returns `M_FORBIDDEN` (instead of `M_INVALID_PARAM`) when an event
fails authorization, and quiets a verbose PDU warning down to a silent skip.

## What changed vs step 128

**Nothing in `src/` — this directory was a byte-identical copy.** The commit
is fully implemented in the modern chain as step 120
(`120_989d843c_forbidden_pdu_context`), which also folds the adjacent
`90cd11d8` (invite → Forbidden), `c1b2b468` (bounds-safe slicing) and
`3e2f742f` (create event first in invite state):

| Rust change | Where it lives |
|---|---|
| **Unauthorized PDU builds → `Forbidden`** | Step 120 — every user-facing auth failure already returns 403 `M_FORBIDDEN` |
| **Verbose PDU warn reverted to silent skip** | Step 120 — the warn added earlier is reverted |
| **Richer invalid-PDU log context** | Step 120 — malformed send_join PDUs log a warning and are skipped |
| **`debug!` → `trace!` for key loading** | Log-level only, no behavior change |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit129 && ./build/tests
```
