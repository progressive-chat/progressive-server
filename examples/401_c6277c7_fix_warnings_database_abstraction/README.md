# Step 401 — "Fix warnings in database::abstraction" (Conduit `c6277c7`)

Source: [`timokoesters/conduit@c6277c7`](https://github.com/timokoesters/conduit/commit/c6277c7) (2022-01)

## What changed vs step 400

| Rust change | C++ translation |
|---|---|
| Fix warnings in database::abstraction. Compiler warning fixes in DB abstraction layer. | **No-op for us** — Rust compiler warnings — our C++ compiles clean. |

## Implementation details

- Rust compiler warnings — our C++ compiles clean.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
