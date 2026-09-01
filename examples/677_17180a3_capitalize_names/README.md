# Step 677 — "capitalize names" (Conduit `17180a3`)

Source: [`timokoesters/conduit@17180a3`](https://github.com/timokoesters/conduit/commit/17180a3) (2023-07)

## What changed vs step 676

| Rust change | C++ translation |
|---|---|
| Capitalize names. Code style/formatting. | **No-op for us** — Code style — our C++ uses its own conventions. |

## Implementation details

- Code style — our C++ uses its own conventions.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
