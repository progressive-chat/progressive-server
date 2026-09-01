# Step 38 — "fix: synapse complains about missing origin" (Conduit `f4078a2`)

Source: [`timokoesters/conduit@f4078a2`](https://github.com/timokoesters/conduit/commit/f4078a2) (2020-09-16)

## What changed vs step 37

| Rust change | C++ translation |
|---|---|
| **Add origin to PDU JSON** before signing | **Translated** — Added origin field to PDU JSON in `append_pdu` |
| **Remove transaction_id from unsigned** in sending | **Translated** — Remove transaction_id from unsigned in send_transaction_message_route |

## Implementation details

1. **Add origin to PDU JSON**: Before signing the PDU, add the origin field with the server name
2. **Remove transaction_id from unsigned**: In send_transaction_message_route, remove transaction_id from unsigned field

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
