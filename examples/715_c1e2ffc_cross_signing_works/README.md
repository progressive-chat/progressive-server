# Step 715 — "improvement: maybe cross signing really works now" (Conduit `c1e2ffc`)

Source: [`timokoesters/conduit@c1e2ffc`](https://github.com/timokoesters/conduit/commit/c1e2ffc) (2023-08)

## What changed vs step 714

| Rust change | C++ translation |
|---|---|
| Improvement: maybe cross signing really works now. Cross-signing (E2EE key verification) implementation. 7 files changed. MAJOR. | **Translated** — We don't have cross-signing yet. This adds cross-signing support. |

## Implementation details

- We don't have cross-signing yet. This adds cross-signing support.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
