# Step 43 — "fix: random timeline reloads" (Conduit `12b0efa`)

Source: [`timokoesters/conduit@12b0efa`](https://github.com/timokoesters/conduit/commit/12b0efa) (2020-10-18)

## What changed vs step 42

| Rust change | C++ translation |
|---|---|
| **Pre-computes `count` and `pdu_id`** before calling `append_pdu` | **Translated** — Pre-compute count and pdu_id to ensure consistency |
| **Appends to state before appending PDU** to prevent race conditions | **Translated** — Append to state first, then append PDU |
| **Changes `append_pdu` signature** to take `count` and `pdu_id` as parameters | **Translated** — Updated `pdu_append` to accept pre-computed count and pdu_id |
| **Same fix applied in `send_transaction_message_route`** | **Translated** — Applied same fix in federation transaction handler |
| **Fixed sync** to handle missing first_pdu_after_since | **Translated** — Fixed sync to handle edge case |

## Implementation details

1. **Pre-compute `count` and `pdu_id`** before calling `append_pdu` to ensure consistency
2. **Append to state before appending PDU** to prevent race conditions where the PDU exists without its state
3. **Updated `pdu_append` signature** to accept pre-computed `count` and `pdu_id` as parameters
4. **Same fix applied in federation transaction handler** for consistency
5. **Fixed sync edge case** where first_pdu_after_since might be missing

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
