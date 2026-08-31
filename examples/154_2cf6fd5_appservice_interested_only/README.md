# Step 154 — "improvement: don't send pdus to appservices if it isn't interested" (Conduit `2cf6fd5`)

Source: [`timokoesters/conduit@2cf6fd5`](https://github.com/timokoesters/conduit/commit/2cf6fd5) (2020-12)

## What changed vs step 153

| Rust change | C++ translation |
|---|---|
| Improvement: don't send PDUs to appservices if it isn't interested. Appservices register interest in specific event types/rooms; we only send matching events. | **Translated** — Our appservice dispatch (step 96) checks the appservice's `sender` field against the event's sender. A more granular namespace check is in step 98 (`308627113`). |

## Implementation details

- Our appservice dispatch (step 96) checks the appservice's `sender` field against the event's sender. A more granular namespace check is in step 98 (`308627113`).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
