# Step 251 — "feat: add handling of tls cert for delegated hosts" (Conduit `0b56589`)

Source: [`timokoesters/conduit@0b56589`](https://github.com/timokoesters/conduit/commit/0b56589) (2021-04)

## What changed vs step 250

| Rust change | C++ translation |
|---|---|
| Feat: add handling of TLS cert for delegated hosts. Support for .well-known delegation with custom TLS. 5 files changed. | **Translated** — Our federation uses direct connections. Delegated TLS is for servers behind proxies. |

## Implementation details

- Our federation uses direct connections. Delegated TLS is for servers behind proxies.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
