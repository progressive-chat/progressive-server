# Step 482 — "fixed location of lowercase fn" (Conduit `8bafdc4`)

Source: [`timokoesters/conduit@8bafdc4`](https://github.com/timokoesters/conduit/commit/8bafdc4) (2022-03)

## What changed vs step 481

| Rust change | C++ translation |
|---|---|
| Fixed location of lowercase fn. Function placement fix. | **No-op for us** — Rust function organization — our C++ structure is different. |

## Implementation details

- Rust function organization — our C++ structure is different.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
