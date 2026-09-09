# Step 122 — "Fix redacted_because field being sent as a string" (Conduit `ddcf1a71`)

Source: [`timokoesters/conduit@ddcf1a71`](https://github.com/timokoesters/conduit/commit/ddcf1a71) (2021-05-26)

Folds in `7db59c55` (return successful PDUs in `/send`) and documents
`deacdf6f` (local-invite `is_direct` — already compliant since step 116).

## What changed vs step 121

| Rust change | C++ translation |
|---|---|
| **`redacted_because` as object, not JSON string** | **Implemented correctly from the start** — `redact_pdu()` never emitted the field before; it now sets `unsigned.redacted_because` to the redaction event object (new optional param, passed by the redact route) |
| **`/send` returns per-PDU results** | **Implemented** — the transaction handler now returns `{event_id: {}}` per stored PDU and `{event_id: {errcode, error}}` per rejected one, instead of a constant empty map |
| **`deacdf6f`: `is_direct` for locally invited users** | **Already compliant** — local invite content has carried `is_direct` since step 116; verified again |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
