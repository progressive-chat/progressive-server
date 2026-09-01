# Step 566 — "Move room version 10 out of experimental/unstable" (Conduit `1e1a144`)

Source: [`timokoesters/conduit@1e1a144`](https://github.com/timokoesters/conduit/commit/1e1a144) (2022-10)

## What changed vs step 565

| Rust change | C++ translation |
|---|---|
| Move room version 10 out of experimental/unstable. Room version 10 stabilization. | **Translated** — Our room versions don't have v10 yet. This would add it. |

## Implementation details

- Our room versions don't have v10 yet. This would add it.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
