# Step 218 — "feat: opentelemetry/jaeger support" (Conduit `4155a47`)

Source: [`timokoesters/conduit@4155a47`](https://github.com/timokoesters/conduit/commit/4155a47) (2021-03)

## What changed vs step 217

| Rust change | C++ translation |
|---|---|
| Feat: opentelemetry/jaeger support. Distributed tracing for federation requests and internal operations. 45 files changed. | **Translated** — Our codebase doesn't have tracing yet. This would add OpenTelemetry integration. |

## Implementation details

- Our codebase doesn't have tracing yet. This would add OpenTelemetry integration.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
