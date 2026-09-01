# Step 626 — "More logging for remote joins" (Conduit `4617ee2`)

Source: [`timokoesters/conduit@4617ee2`](https://github.com/timokoesters/conduit/commit/4617ee2) (2023-03)

## What changed vs step 625

| Rust change | C++ translation |
|---|---|
| More logging for remote joins. Debug logging for federation joins. 2 files changed. | **Translated** — Our remote joins (step 25, 93) log. This adds more debug in Rust. |

## Implementation details

- Our remote joins (step 25, 93) log. This adds more debug in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
