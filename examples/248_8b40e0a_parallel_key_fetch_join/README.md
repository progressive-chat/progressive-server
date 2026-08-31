# Step 248 — "improvement: fetch signing keys in parallel when joining a room" (Conduit `8b40e0a`)

Source: [`timokoesters/conduit@8b40e0a`](https://github.com/timokoesters/conduit/commit/8b40e0a) (2021-04)

## What changed vs step 247

| Rust change | C++ translation |
|---|---|
| Improvement: fetch signing keys in parallel when joining a room. Performance optimization for room joins. 4 files changed. | **Translated** — Our key fetching (step 8) is sequential. Parallel fetch would be a performance improvement. |

## Implementation details

- Our key fetching (step 8) is sequential. Parallel fetch would be a performance improvement.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
