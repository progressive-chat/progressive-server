# Step 108 — "Change license to Apache-2.0" (Conduit `a2dbc6f`)

Source: [`timokoesters/conduit@a2dbc6f`](https://github.com/timokoesters/conduit/commit/a2dbc6f) (2020-10)

## What changed vs step 107

| Rust change | C++ translation |
|---|---|
| Changes the license from MIT to Apache-2.0. | **No-op for us** — Our project has its own license. License changes don't affect the code. |

## Implementation details

- Our project has its own license. License changes don't affect the code.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
