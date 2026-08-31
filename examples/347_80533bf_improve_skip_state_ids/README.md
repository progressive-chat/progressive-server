# Step 347 — "fix: improve code when skipping /state_ids" (Conduit `80533bf`)

Source: [`timokoesters/conduit@80533bf`](https://github.com/timokoesters/conduit/commit/80533bf) (2021-07)

## What changed vs step 346

| Rust change | C++ translation |
|---|---|
| Fix: improve code when skipping /state_ids. Optimization for state_ids endpoint. | **Translated** — Our /state_ids (step 227) skips efficiently. This improves the Rust version. |

## Implementation details

- Our /state_ids (step 227) skips efficiently. This improves the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
