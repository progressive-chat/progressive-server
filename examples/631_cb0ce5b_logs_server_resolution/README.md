# Step 631 — "Logs for server resolution" (Conduit `cb0ce5b`)

Source: [`timokoesters/conduit@cb0ce5b`](https://github.com/timokoesters/conduit/commit/cb0ce5b) (2023-03)

## What changed vs step 630

| Rust change | C++ translation |
|---|---|
| Logs for server resolution. DNS/SRV resolution logging. 1 file changed. | **Translated** — Our federation (step 29) resolves servers. This adds resolution logs. |

## Implementation details

- Our federation (step 29) resolves servers. This adds resolution logs.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
