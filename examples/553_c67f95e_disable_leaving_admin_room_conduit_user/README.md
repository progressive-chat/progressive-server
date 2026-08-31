# Step 553 — "feat(db/rooms): disable leaving from admin room for conduit user" (Conduit `c67f95e`)

Source: [`timokoesters/conduit@c67f95e`](https://github.com/timokoesters/conduit/commit/c67f95e) (2022-10)

## What changed vs step 552

| Rust change | C++ translation |
|---|---|
| Feat(db/rooms): disable leaving from admin room for conduit user. Conduit system user can't leave admin room. | **Translated** — Our admin room (step 60) retains the system user. This enforces it in Rust. |

## Implementation details

- Our admin room (step 60) retains the system user. This enforces it in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
