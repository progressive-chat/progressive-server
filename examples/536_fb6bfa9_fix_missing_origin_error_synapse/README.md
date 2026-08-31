# Step 536 — "fix: missing field `origin` error with synapse servers" (Conduit `fb6bfa9`)

Source: [`timokoesters/conduit@fb6bfa9`](https://github.com/timokoesters/conduit/commit/fb6bfa9) (2022-10)

## What changed vs step 535

| Rust change | C++ translation |
|---|---|
| Fix: missing field `origin` error with synapse servers. Handle missing origin field in federation requests from Synapse. | **Translated** — Our federation (step 29) handles origin. This fixes a Synapse compatibility issue. |

## Implementation details

- Our federation (step 29) handles origin. This fixes a Synapse compatibility issue.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
