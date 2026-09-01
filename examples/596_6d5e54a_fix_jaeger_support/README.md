# Step 596 — "fix: jaeger support" (Conduit `6d5e54a`)

Source: [`timokoesters/conduit@6d5e54a`](https://github.com/timokoesters/conduit/commit/6d5e54a) (2022-12)

## What changed vs step 595

| Rust change | C++ translation |
|---|---|
| Fix: jaeger support. Distributed tracing fixes. 9 files changed. | **Translated** — Related to step 218 (opentelemetry/jaeger). This fixes the Rust implementation. |

## Implementation details

- Related to step 218 (opentelemetry/jaeger). This fixes the Rust implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
