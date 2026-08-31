# Step 488 — "Fix crash when a bad user ID is in the database" (Conduit `4a12a7c`)

Source: [`timokoesters/conduit@4a12a7c`](https://github.com/timokoesters/conduit/commit/4a12a7c) (2022-03)

## What changed vs step 487

| Rust change | C++ translation |
|---|---|
| Fix crash when a bad user ID is in the database. Validate user IDs from DB. | **Translated** — Our user ID validation (step 10) prevents bad IDs. This adds a Rust safety check. |

## Implementation details

- Our user ID validation (step 10) prevents bad IDs. This adds a Rust safety check.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
