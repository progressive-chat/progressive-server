# Step 311 — "fix fmt problems" (Conduit `2078af5`)

Source: [`timokoesters/conduit@2078af5`](https://github.com/timokoesters/conduit/commit/2078af5) (2021-06)

## What changed vs step 310

| Rust change | C++ translation |
|---|---|
| Fix fmt problems. Code formatting fixes. | **No-op for us** — Rust fmt — our C++ uses clang-format. |

## Implementation details

- Rust fmt — our C++ uses clang-format.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
