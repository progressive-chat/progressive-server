# Step 272 — "Bump ruma" (Conduit `c28eba1`)

Source: [`timokoesters/conduit@c28eba1`](https://github.com/timokoesters/conduit/commit/c28eba1) (2021-04)

## What changed vs step 271

| Rust change | C++ translation |
|---|---|
| Bump ruma. Another dependency bump. 3 files changed. | **Skipped** — Rust dependency bump. |

## Implementation details

- Rust dependency bump.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
