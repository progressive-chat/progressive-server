# Step 485 — "Use native root CA certificates for reqwest" (Conduit `194a85d`)

Source: [`timokoesters/conduit@194a85d`](https://github.com/timokoesters/conduit/commit/194a85d) (2022-03)

## What changed vs step 484

| Rust change | C++ translation |
|---|---|
| Use native root CA certificates for reqwest. TLS certificate trust store. 2 files changed. | **Translated** — Our federation client (step 29) uses system CA. This configures native roots in Rust. |

## Implementation details

- Our federation client (step 29) uses system CA. This configures native roots in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
