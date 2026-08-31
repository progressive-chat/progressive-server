# Step 426 — "tests" (Conduit `e17bbdd`)

Source: [`timokoesters/conduit@e17bbdd`](https://github.com/timokoesters/conduit/commit/e17bbdd) (2022-01)

## What changed vs step 425

| Rust change | C++ translation |
|---|---|
| Tests. Test additions. | **No-op for us** — Rust tests — our C++ has its own tests. |

## Implementation details

- Rust tests — our C++ has its own tests.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
