# Step 752 — "add script to build and push to binary cache" (Conduit `bdc46f6`)

Source: [`timokoesters/conduit@bdc46f6`](https://github.com/timokoesters/conduit/commit/bdc46f6) (2024-01)

## What changed vs step 751

| Rust change | C++ translation |
|---|---|
| Add script to build and push to binary cache. CI binary cache script. 3 files changed. | **Skipped** — CI only. |

## Implementation details

- CI only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
