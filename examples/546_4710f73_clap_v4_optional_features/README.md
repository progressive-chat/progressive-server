# Step 546 — "clap v4 turned more things into optional features" (Conduit `4710f73`)

Source: [`timokoesters/conduit@4710f73`](https://github.com/timokoesters/conduit/commit/4710f73) (2022-10)

## What changed vs step 545

| Rust change | C++ translation |
|---|---|
| clap v4 turned more things into optional features. CLI library feature changes. | **No-op for us** — Rust clap library — our C++ uses different CLI parsing. |

## Implementation details

- Rust clap library — our C++ uses different CLI parsing.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
