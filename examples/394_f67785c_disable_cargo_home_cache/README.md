# Step 394 — "Fix(ci): Disable CARGO_HOME caching" (Conduit `f67785c`)

Source: [`timokoesters/conduit@f67785c`](https://github.com/timokoesters/conduit/commit/f67785c) (2022-01)

## What changed vs step 393

| Rust change | C++ translation |
|---|---|
| Fix(ci): Disable CARGO_HOME caching. CI cache configuration fix. | **No-op for us** — Rust CI cache — our CMake doesn't use CARGO_HOME. |

## Implementation details

- Rust CI cache — our CMake doesn't use CARGO_HOME.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
