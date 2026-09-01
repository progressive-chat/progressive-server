# Step 667 — "feat: space hierarchies" (Conduit `9d49d59`)

Source: [`timokoesters/conduit@9d49d59`](https://github.com/timokoesters/conduit/commit/9d49d59) (2023-07)

## What changed vs step 666

| Rust change | C++ translation |
|---|---|
| Feat: space hierarchies. Space (room hierarchy) support. 11 files changed. MAJOR feature. | **Translated** — We don't have spaces yet. This adds MSC2946 space hierarchies. |

## Implementation details

- We don't have spaces yet. This adds MSC2946 space hierarchies.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
