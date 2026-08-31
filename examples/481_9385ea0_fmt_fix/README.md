# Step 481 — "fmt fix" (Conduit `9385ea0`)

Source: [`timokoesters/conduit@9385ea0`](https://github.com/timokoesters/conduit/commit/9385ea0) (2022-03)

## What changed vs step 480

| Rust change | C++ translation |
|---|---|
| fmt fix. Code formatting fix. | **No-op for us** — Rust fmt — our C++ uses clang-format. |

## Implementation details

- Rust fmt — our C++ uses clang-format.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
