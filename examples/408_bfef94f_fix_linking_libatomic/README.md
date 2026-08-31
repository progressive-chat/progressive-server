# Step 408 — "fix: linking against libatomic is no longer required since the library path is fixed" (Conduit `bfef94f`)

Source: [`timokoesters/conduit@bfef94f`](https://github.com/timokoesters/conduit/commit/bfef94f) (2022-01)

## What changed vs step 407

| Rust change | C++ translation |
|---|---|
| Fix: linking against libatomic is no longer required since the library path is fixed. Build system fix. | **No-op for us** — Rust build system linking — our CMake handles linking. |

## Implementation details

- Rust build system linking — our CMake handles linking.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
