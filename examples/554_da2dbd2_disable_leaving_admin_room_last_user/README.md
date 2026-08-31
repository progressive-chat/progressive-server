# Step 554 — "feat(db/rooms): disable leaving from admin room for last user" (Conduit `da2dbd2`)

Source: [`timokoesters/conduit@da2dbd2`](https://github.com/timokoesters/conduit/commit/da2dbd2) (2022-10)

## What changed vs step 553

| Rust change | C++ translation |
|---|---|
| Feat(db/rooms): disable leaving from admin room for last user. Prevent admin room from becoming empty. | **Translated** — Our admin room (step 60) retains at least one user. This enforces it in Rust. |

## Implementation details

- Our admin room (step 60) retains at least one user. This enforces it in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
