# Step 230 — "fix: signature key fetching, optimize push sending" (Conduit `363c629`)

Source: [`timokoesters/conduit@363c629`](https://github.com/timokoesters/conduit/commit/363c629) (2021-03)

## What changed vs step 229

| Rust change | C++ translation |
|---|---|
| Fix: signature key fetching, optimize push sending. Better key fetching logic and push optimization. 7 files changed. | **Translated** — Our key fetching (step 8) and push (steps 186-187) cover this. These are improvements. |

## Implementation details

- Our key fetching (step 8) and push (steps 186-187) cover this. These are improvements.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
