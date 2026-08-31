# Step 344 — "feat: /keys/query and /keys/claim over federation" (Conduit `728e176`)

Source: [`timokoesters/conduit@728e176`](https://github.com/timokoesters/conduit/commit/728e176) (2021-07)

## What changed vs step 343

| Rust change | C++ translation |
|---|---|
| Feat: /keys/query and /keys/claim over federation. Federation key querying and claiming. 2 files changed. MAJOR encryption feature. | **Translated** — Our key fetching (step 8) is local. This adds federation key operations. |

## Implementation details

- Our key fetching (step 8) is local. This adds federation key operations.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
