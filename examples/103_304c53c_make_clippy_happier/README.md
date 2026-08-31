# Step 103 — "style: make clippy happier" (Conduit `304c53c`)

Source: [`timokoesters/conduit@304c53c`](https://github.com/timokoesters/conduit/commit/304c53c) (2020-10)

## What changed vs step 102

| Rust change | C++ translation |
|---|---|
| Style: make clippy (Rust linter) happier. Whitespace and naming cleanups. | **No-op for us** — Rust linter changes — N/A for C++. |

## Implementation details

- Rust linter changes — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
