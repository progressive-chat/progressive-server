# Step 458 — "take advantage of multiple paths" (Conduit `b8d92d3`)

Source: [`timokoesters/conduit@b8d92d3`](https://github.com/timokoesters/conduit/commit/b8d92d3) (2022-02)

## What changed vs step 457

| Rust change | C++ translation |
|---|---|
| Take advantage of multiple paths. Route/path optimization. 3 files changed. | **Translated** — Our routing (httplib) handles multiple paths. This optimizes the Rust version. |

## Implementation details

- Our routing (httplib) handles multiple paths. This optimizes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
