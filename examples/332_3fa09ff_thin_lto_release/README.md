# Step 332 — "Use thin-lto [1] for "better" release builds." (Conduit `3fa09ff`)

Source: [`timokoesters/conduit@3fa09ff`](https://github.com/timokoesters/conduit/commit/3fa09ff) (2021-07)

## What changed vs step 331

| Rust change | C++ translation |
|---|---|
| Use thin-lto for better release builds. Link-time optimization. | **No-op for us** — Rust LTO — our C++ uses standard LTO via CMake. |

## Implementation details

- Rust LTO — our C++ uses standard LTO via CMake.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
