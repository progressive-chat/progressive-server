# Step 683 — "only listen on IPv6 since that's what conduit does" (Conduit `6ae5143`)

Source: [`timokoesters/conduit@6ae5143`](https://github.com/timokoesters/conduit/commit/6ae5143) (2023-07)

## What changed vs step 682

| Rust change | C++ translation |
|---|---|
| Only listen on IPv6 since that's what conduit does. IPv6-only listening. 1 file changed. | **Translated** — Our server (step 6) listens on both IPv4/IPv6. This makes it IPv6-only in Rust. |

## Implementation details

- Our server (step 6) listens on both IPv4/IPv6. This makes it IPv6-only in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
