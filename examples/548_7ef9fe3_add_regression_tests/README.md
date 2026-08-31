# Step 548 — "add regression tests" (Conduit `7ef9fe3`)

Source: [`timokoesters/conduit@7ef9fe3`](https://github.com/timokoesters/conduit/commit/7ef9fe3) (2022-10)

## What changed vs step 547

| Rust change | C++ translation |
|---|---|
| Add regression tests. Test additions. | **No-op for us** — Rust tests — our C++ has its own tests. |

## Implementation details

- Rust tests — our C++ has its own tests.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
