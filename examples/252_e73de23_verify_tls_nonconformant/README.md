# Step 252 — "fix: verify tls cert for non-conformant servers" (Conduit `e73de23`)

Source: [`timokoesters/conduit@e73de23`](https://github.com/timokoesters/conduit/commit/e73de23) (2021-04)

## What changed vs step 251

| Rust change | C++ translation |
|---|---|
| Fix: verify TLS cert for non-conformant servers. Some servers have bad TLS config; handle gracefully. | **Translated** — Our TLS handling uses standard verification. This adds workarounds for bad configs. |

## Implementation details

- Our TLS handling uses standard verification. This adds workarounds for bad configs.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
