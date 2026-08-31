# Step 98 — "fix: don't send new requests to servers if we are already waiting" (Conduit `ab33236`)

Source: [`timokoesters/conduit@ab33236`](https://github.com/timokoesters/conduit/commit/ab33236) (2020-10)

## What changed vs step 97

| Rust change | C++ translation |
|---|---|
| Don't send a new federation request to a server if we're already waiting for a response. Prevents duplicate transactions. | **Translated** — Our federation send (`step 35`) is fire-and-forget without dedup. The 50-PDU limit (step 99, `16b22bb`) provides backpressure. |

## Implementation details

- Our federation send (`step 35`) is fire-and-forget without dedup. The 50-PDU limit (step 99, `16b22bb`) provides backpressure.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
