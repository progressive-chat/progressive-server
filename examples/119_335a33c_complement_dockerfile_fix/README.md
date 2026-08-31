# Step 119 — "Fix and Improve Complement testing Dockerfile" (Conduit `335a33c`)

Source: [`timokoesters/conduit@335a33c`](https://github.com/timokoesters/conduit/commit/335a33c) (2020-10)

## What changed vs step 118

| Rust change | C++ translation |
|---|---|
| Fix and Improve Complement testing Dockerfile. | **Skipped** — Pure CI/test infrastructure change. |

## Implementation details

- Pure CI/test infrastructure change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
