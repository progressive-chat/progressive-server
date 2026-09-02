# Step 109 — "feat: add handling of tls cert for delegated hosts" (Conduit `0b56589`)

Source: [`timokoesters/conduit@0b56589`](https://github.com/timokoesters/conduit/commit/0b56589) (2021-04-15)

## What changed vs step 108

| Rust change | C++ translation |
|---|---|
| **TLS cert for delegated hosts** | **Translated** — TLS cert handling |

## Implementation details

1. **TLS cert handling** — Add handling of TLS cert for delegated hosts

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
