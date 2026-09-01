# Step 635 — "Don't crash when a room errors" (Conduit `42b1293`)

Source: [`timokoesters/conduit@42b1293`](https://github.com/timokoesters/conduit/commit/42b1293) (2023-03)

## What changed vs step 634

| Rust change | C++ translation |
|---|---|
| Don't crash when a room errors. Prevent server crash on room-level errors. | **Translated** — Our room handling (step 83) catches errors. This prevents a Rust crash. |

## Implementation details

- Our room handling (step 83) catches errors. This prevents a Rust crash.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
