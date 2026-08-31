# Step 547 — "resolve `cargo check --features clap/deprecated`" (Conduit `fc852f8`)

Source: [`timokoesters/conduit@fc852f8`](https://github.com/timokoesters/conduit/commit/fc852f8) (2022-10)

## What changed vs step 546

| Rust change | C++ translation |
|---|---|
| Resolve `cargo check --features clap/deprecated`. Feature flag resolution. | **No-op for us** — Rust feature flags — N/A for C++. |

## Implementation details

- Rust feature flags — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
