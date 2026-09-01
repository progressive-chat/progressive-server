# Step 614 — "add little readme" (Conduit `e13dc7c`)

Source: [`timokoesters/conduit@e13dc7c`](https://github.com/timokoesters/conduit/commit/e13dc7c) (2023-01)

## What changed vs step 613

| Rust change | C++ translation |
|---|---|
| Add little readme. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
