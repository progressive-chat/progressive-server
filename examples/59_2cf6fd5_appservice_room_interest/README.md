# Step 59 — "improvement: don't send pdus to appservices if it isn't interested" (Conduit `2cf6fd5`)

Source: [`timokoesters/conduit@2cf6fd5`](https://github.com/timokoesters/conduit/commit/2cf6fd5) (2020-12-23)

## What changed vs step 58

| Rust change | C++ translation |
|---|---|
| **Don't send PDUs to appservices if not interested** | **Translated** — Check appservice interest in room |
| **Appservice interest check** | **Translated** — AppserviceManager::is_interested() |
| **TODO: send pdus if user of appservice is in room** | **Translated** — Noted as TODO |

## Implementation details

1. **Appservice interest check** — Appservices only get PDUs for rooms they're interested in
2. **Room filtering** — Filter PDUs by appservice room interest
3. **TODO marker** — Noted that we need to also send PDUs if a user of the appservice is in the room

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
