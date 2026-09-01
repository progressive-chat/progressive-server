# Step 672 — "fix: better sliding sync" (Conduit `78e7b71`)

Source: [`timokoesters/conduit@78e7b71`](https://github.com/timokoesters/conduit/commit/78e7b71) (2023-07)

## What changed vs step 671

| Rust change | C++ translation |
|---|---|
| Fix: better sliding sync. Sliding sync fixes. 1 file changed. | **Translated** — Follows step 670 — fixes for sliding sync. |

## Implementation details

- Follows step 670 — fixes for sliding sync.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
