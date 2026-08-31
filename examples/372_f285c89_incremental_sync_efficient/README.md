# Step 372 — "fix: make incremental sync efficient again" (Conduit `f285c89`)

Source: [`timokoesters/conduit@f285c89`](https://github.com/timokoesters/conduit/commit/f285c89) (2022-01)

## What changed vs step 371

| Rust change | C++ translation |
|---|---|
| Fix: make incremental sync efficient again. Restore incremental /sync performance. 3 files changed. | **Translated** — Our /sync (step 6) does incremental sync. This restores efficiency in Rust. |

## Implementation details

- Our /sync (step 6) does incremental sync. This restores efficiency in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
