# Step 249 — "feat: join cursed rooms" (Conduit `5951294`)

Source: [`timokoesters/conduit@5951294`](https://github.com/timokoesters/conduit/commit/5951294) (2021-04)

## What changed vs step 248

| Rust change | C++ translation |
|---|---|
| Feat: join cursed rooms. Handle rooms with weird/corrupted state that would normally fail to join. 5 files changed. | **Translated** — Our state-res (step 83) handles edge cases. Cursed rooms need special handling in state resolution. |

## Implementation details

- Our state-res (step 83) handles edge cases. Cursed rooms need special handling in state resolution.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
