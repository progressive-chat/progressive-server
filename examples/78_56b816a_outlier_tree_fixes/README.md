# Step 78 — "Fix and integrate outlier tree, build forks after adding event to DB" (Conduit `56b816a`)

Source: [`timokoesters/conduit@56b816a`](https://github.com/timokoesters/conduit/commit/56b816a) (2021-01-29)

## What changed vs step 77

| Rust change | C++ translation |
|---|---|
| **Fix and integrate outlier tree** | **Partial** — Outlier tree structure updated |
| **Build forks after adding event to DB** | **Partial** — Fork building exists but not fully integrated |

## Implementation details

This commit significantly changes the outlier tree structure:

1. **Renamed `eventid_outlierpdu` to `pduid_outlierpdu`** — Now maps pdu_id to outlier PDU
2. **Added `eventid_pduid` tree** — Maps event_id to pdu_id for outlier lookup
3. **Outlier lookup now uses two-step lookup** — event_id -> pdu_id -> outlier PDU
4. **`append_pdu_outlier` now takes pdu_id** instead of event_id
5. **Outlier lookup uses two-step lookup** — event_id -> pdu_id -> outlier PDU
6. **`append_pdu_outlier` now stores event_id -> pdu_id mapping** in `eventid_pduid`

**In our C++ implementation:** Our database has `eventid_outlierpdu` but we don't have the `eventid_pduid` mapping or the `pduid_outlierpdu` rename. Our outlier handling is simpler.

**Status:** Partially implemented — our outlier tree is simpler

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
