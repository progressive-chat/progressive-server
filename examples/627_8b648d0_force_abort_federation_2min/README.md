# Step 627 — "fix: force abort federation requests after 2 minutes" (Conduit `8b648d0`)

Source: [`timokoesters/conduit@8b648d0`](https://github.com/timokoesters/conduit/commit/8b648d0) (2023-03)

## What changed vs step 626

| Rust change | C++ translation |
|---|---|
| Fix: force abort federation requests after 2 minutes. Timeout for federation requests. 1 file changed. | **Translated** — Our federation (step 29) has timeouts. This enforces 2-minute limit. |

## Implementation details

- Our federation (step 29) has timeouts. This enforces 2-minute limit.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
