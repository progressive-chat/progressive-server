# Step 695 — "It's ok not being able to find a .well-known response." (Conduit `7990822`)

Source: [`timokoesters/conduit@7990822`](https://github.com/timokoesters/conduit/commit/7990822) (2023-07)

## What changed vs step 694

| Rust change | C++ translation |
|---|---|
| It's ok not being able to find a .well-known response. Handle missing .well-known gracefully. | **Translated** — Our .well-known handling (step 10) handles missing responses. This ensures graceful handling. |

## Implementation details

- Our .well-known handling (step 10) handles missing responses. This ensures graceful handling.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
