# Step 585 — "Moving the unwraping of a variable" (Conduit `a2d8aec`)

Source: [`timokoesters/conduit@a2d8aec`](https://github.com/timokoesters/conduit/commit/a2d8aec) (2022-11)

## What changed vs step 584

| Rust change | C++ translation |
|---|---|
| Moving the unwraping of a variable. Code reorganization. | **No-op for us** — Rust unwrap reorganization — our C++ doesn't use unwrap. |

## Implementation details

- Rust unwrap reorganization — our C++ doesn't use unwrap.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
