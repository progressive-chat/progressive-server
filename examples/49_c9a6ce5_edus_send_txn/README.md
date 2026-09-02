# Step 49 — "Add basic handling of EDUs for /send/txn" (Conduit `c9a6ce5`)

Source: [`timokoesters/conduit@c9a6ce5`](https://github.com/timokoesters/conduit/commit/c9a6ce5) (2020-12-05)

## What changed vs step 48

| Rust change | C++ translation |
|---|---|
| **Added EDU handling in `/send/txn` route** | **Translated** — Added EDU handling in `send_transaction_message_route` |
| **Handle `m.typing` EDUs** (typing notifications) | **Translated** — Added typing EDU handling |
| **Handle `m.presence` EDUs** (presence updates) | **Translated** — Placeholder for presence EDU handling |
| **Handle `m.receipt` EDUs** (read receipts) | **Translated** — Placeholder for receipt EDU handling |

## Implementation details

1. **EDU processing in `/send/txn`**: Added loop to iterate through EDUs in the transaction
2. **Typing EDU handling**: 
   - Add typing user when `typing` is true
   - Remove typing user when `typing` is false
3. **Presence EDU**: Placeholder for future implementation
4. **Receipt EDU**: Placeholder for future implementation
5. **Error handling**: Log errors but continue processing other EDUs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
