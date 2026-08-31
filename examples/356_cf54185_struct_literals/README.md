# Step 356 — "Use struct literals for consistency" (Conduit `cf54185`)

Source: [`timokoesters/conduit@cf54185`](https://github.com/timokoesters/conduit/commit/cf54185) (2022-01)

## What changed vs step 355

| Rust change | C++ translation |
|---|---|
| Use struct literals for consistency. Rust code style improvement. 3 files changed. | **No-op for us** — Rust struct literal syntax — our C++ uses different initialization. |

## Implementation details

- Rust struct literal syntax — our C++ uses different initialization.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
