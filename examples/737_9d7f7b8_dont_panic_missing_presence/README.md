# Step 737 — "don't panic on missing presence status for a user" (Conduit `9d7f7b8`)

Source: [`timokoesters/conduit@9d7f7b8`](https://github.com/timokoesters/conduit/commit/9d7f7b8) (2023-12)

## What changed vs step 736

| Rust change | C++ translation |
|---|---|
| Don't panic on missing presence status for a user. Presence status handling. 1 file changed. | **Translated** — We don't have presence yet (gap from 2020). This prevents panic in Rust. |

## Implementation details

- We don't have presence yet (gap from 2020). This prevents panic in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
