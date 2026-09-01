# Step 591 — "Added cross-compilation instructions to DEPLOY.md" (Conduit `bcd522e`)

Source: [`timokoesters/conduit@bcd522e`](https://github.com/timokoesters/conduit/commit/bcd522e) (2022-11)

## What changed vs step 590

| Rust change | C++ translation |
|---|---|
| Added cross-compilation instructions to DEPLOY.md. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
