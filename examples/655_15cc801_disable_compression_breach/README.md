# Step 655 — "Disable compression, see https://en.wikipedia.org/wiki/BREACH" (Conduit `15cc801`)

Source: [`timokoesters/conduit@15cc801`](https://github.com/timokoesters/conduit/commit/15cc801) (2023-06)

## What changed vs step 654

| Rust change | C++ translation |
|---|---|
| Disable compression, see https://en.wikipedia.org/wiki/BREACH. BREACH attack mitigation. 3 files changed. | **Translated** — Our HTTP server (httplib) doesn't enable compression by default. This disables it in Rust. |

## Implementation details

- Our HTTP server (httplib) doesn't enable compression by default. This disables it in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
