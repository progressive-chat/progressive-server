# Step 137 — "fix: also return successful PDUs in /send/:txnId" (Conduit `7db59c5`)

Source: [`timokoesters/conduit@7db59c5`](https://github.com/timokoesters/conduit/commit/7db59c5) (2021-05-27)

Upstream's federation `/send` handler returns per-PDU results for stored
PDUs instead of a constant empty map.

## What changed vs step 136

**Nothing in `src/` — this directory was a byte-identical copy.** The change
is implemented in the modern chain as part of step 122
(`122_ddcf1a71_redaction_send_receipts`), whose transaction handler returns
`{event_id: {}}` per stored PDU and `{event_id: {errcode, error}}` per
rejected one.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit137 && ./build/tests
```
