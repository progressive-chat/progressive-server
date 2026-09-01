# Step 719 — "More sanity checks" (Conduit `fd9e52a`)

Source: [`timokoesters/conduit@fd9e52a`](https://github.com/timokoesters/conduit/commit/fd9e52a) (2023-08)

## What changed vs step 718

| Rust change | C++ translation |
|---|---|
| More sanity checks. Additional validation checks throughout the codebase. 1 file changed. | **Translated** — Our codebase has validation. This adds more checks in Rust. |

## Implementation details

- Our codebase has validation. This adds more checks in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
