# Step 520 — "fix: some compile time errors" (Conduit `057f836`)

Source: [`timokoesters/conduit@057f836`](https://github.com/timokoesters/conduit/commit/057f836) (2022-10)

## What changed vs step 519

| Rust change | C++ translation |
|---|---|
| Fix: some compile time errors. First batch of compile fixes. 118 files changed. | **No-op for us** — Rust compile fixes after major refactor — our C++ compiles clean. |

## Implementation details

- Rust compile fixes after major refactor — our C++ compiles clean.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
