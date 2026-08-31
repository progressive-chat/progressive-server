# Step 451 — "Port from Rocket to axum" (Conduit `1f7b3fa`)

Source: [`timokoesters/conduit@1f7b3fa`](https://github.com/timokoesters/conduit/commit/1f7b3fa) (2022-02)

## What changed vs step 450

| Rust change | C++ translation |
|---|---|
| Port from Rocket to axum. MAJOR web framework migration! 52 files changed. Complete rewrite of HTTP layer. | **Translated** — Our web framework is httplib (C++). This is a Rust Rocket->axum migration, no direct equivalent. |

## Implementation details

- Our web framework is httplib (C++). This is a Rust Rocket->axum migration, no direct equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
