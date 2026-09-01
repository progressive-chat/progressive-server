# Step 688 — "Also create the conduit (system) group" (Conduit `b1a591a`)

Source: [`timokoesters/conduit@b1a591a`](https://github.com/timokoesters/conduit/commit/b1a591a) (2023-07)

## What changed vs step 687

| Rust change | C++ translation |
|---|---|
| Also create the conduit (system) group. System group creation. | **No-op for us** — System deployment — N/A for C++. |

## Implementation details

- System deployment — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
