# Step 289 — "fix: too many syncs" (Conduit `9b77eb7`)

Source: [`timokoesters/conduit@9b77eb7`](https://github.com/timokoesters/conduit/commit/9b77eb7) (2021-05)

## What changed vs step 288

| Rust change | C++ translation |
|---|---|
| Fix: too many syncs. Prevent excessive /sync requests from clients. | **Translated** — Our /sync (step 6) doesn't rate limit syncs. This adds rate limiting. |

## Implementation details

- Our /sync (step 6) doesn't rate limit syncs. This adds rate limiting.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
