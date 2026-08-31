# Step 298 — "fix: also return successful PDUs in /send/:txnId" (Conduit `7db59c5`)

Source: [`timokoesters/conduit@7db59c5`](https://github.com/timokoesters/conduit/commit/7db59c5) (2021-05)

## What changed vs step 297

| Rust change | C++ translation |
|---|---|
| Fix: also return successful PDUs in /send/:txnId. Response includes both successful and failed PDUs. | **Translated** — Our /send (step 29) returns response per PDU. This ensures successful ones are included. |

## Implementation details

- Our /send (step 29) returns response per PDU. This ensures successful ones are included.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
