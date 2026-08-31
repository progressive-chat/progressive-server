# Step 382 — "improvement: higher default pdu capacity" (Conduit `4476390`)

Source: [`timokoesters/conduit@4476390`](https://github.com/timokoesters/conduit/commit/4476390) (2022-01)

## What changed vs step 381

| Rust change | C++ translation |
|---|---|
| Improvement: higher default pdu capacity. Increase default PDU cache size. 2 files changed. | **Translated** — Our PDU cache (step 320) has a capacity. This increases the default. |

## Implementation details

- Our PDU cache (step 320) has a capacity. This increases the default.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
