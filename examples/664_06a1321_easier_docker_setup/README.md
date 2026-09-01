# Step 664 — "easier-to-read docker setup instructions" (Conduit `06a1321`)

Source: [`timokoesters/conduit@06a1321`](https://github.com/timokoesters/conduit/commit/06a1321) (2023-06)

## What changed vs step 663

| Rust change | C++ translation |
|---|---|
| Easier-to-read docker setup instructions. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
