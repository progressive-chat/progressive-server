# Step 83 — "fix: don't panic on bad server names" (Conduit `0b26320`)

Source: [`timokoesters/conduit@0b26320`](https://github.com/timokoesters/conduit/commit/0b26320) (2020-09)

## What changed vs step 82

| Rust change | C++ translation |
|---|---|
| Don't panic when given a malformed server name in federation send. Validates the destination server name before opening a connection. | We have no equivalent panic because we use string comparison and TLS connection failure is handled gracefully. |

## Implementation details

- We have no equivalent panic because we use string comparison and TLS connection failure is handled gracefully.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
