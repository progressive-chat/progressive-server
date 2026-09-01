# Step 623 — "fix: ignore unparsable pdus in /send" (Conduit `2aa0a24`)

Source: [`timokoesters/conduit@2aa0a24`](https://github.com/timokoesters/conduit/commit/2aa0a24) (2023-03)

## What changed vs step 622

| Rust change | C++ translation |
|---|---|
| Fix: ignore unparsable pdus in /send. Skip invalid PDUs in transaction. 1 file changed. | **Translated** — Our /send (step 29) validates PDUs. This adds graceful skip in Rust. |

## Implementation details

- Our /send (step 29) validates PDUs. This adds graceful skip in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
