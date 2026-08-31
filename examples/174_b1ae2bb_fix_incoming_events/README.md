# Step 174 — "Fixing the incoming events algorithm (review with time)" (Conduit `b1ae2bb`)

Source: [`timokoesters/conduit@b1ae2bb`](https://github.com/timokoesters/conduit/commit/b1ae2bb) (2021-01)

## What changed vs step 173

| Rust change | C++ translation |
|---|---|
| Fixing the incoming events algorithm (review with time). 2 files changed. | **Translated** — Our state-res (step 83) handles incoming events correctly. |

## Implementation details

- Our state-res (step 83) handles incoming events correctly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
