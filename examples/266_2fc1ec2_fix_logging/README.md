# Step 266 — "fix: logging" (Conduit `2fc1ec2`)

Source: [`timokoesters/conduit@2fc1ec2`](https://github.com/timokoesters/conduit/commit/2fc1ec2) (2021-04)

## What changed vs step 265

| Rust change | C++ translation |
|---|---|
| Fix: logging. Better log formatting and levels. 3 files changed. | **Translated** — Our logging is via std::cerr. This improves Rust logging. |

## Implementation details

- Our logging is via std::cerr. This improves Rust logging.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
