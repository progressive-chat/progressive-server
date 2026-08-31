# Step 265 — "improvement: warning on misconfigured reverse proxy" (Conduit `226045e`)

Source: [`timokoesters/conduit@226045e`](https://github.com/timokoesters/conduit/commit/226045e) (2021-04)

## What changed vs step 264

| Rust change | C++ translation |
|---|---|
| Improvement: warning on misconfigured reverse proxy. Detect and warn about common proxy misconfigurations. 3 files changed. | **Translated** — Our server runs directly. This adds a warning if X-Forwarded headers are wrong. |

## Implementation details

- Our server runs directly. This adds a warning if X-Forwarded headers are wrong.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
