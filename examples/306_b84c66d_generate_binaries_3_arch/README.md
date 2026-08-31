# Step 306 — "Generate binaries for 3 architectures in the CI" (Conduit `b84c66d`)

Source: [`timokoesters/conduit@b84c66d`](https://github.com/timokoesters/conduit/commit/b84c66d) (2021-06)

## What changed vs step 305

| Rust change | C++ translation |
|---|---|
| Generate binaries for 3 architectures in the CI. CI/CD for multi-arch builds. | **No-op for us** — CI/CD for Rust — our C++ builds are single-arch. |

## Implementation details

- CI/CD for Rust — our C++ builds are single-arch.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
