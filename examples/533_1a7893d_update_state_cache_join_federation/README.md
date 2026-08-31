# Step 533 — "fix: update state_cache on join over federation" (Conduit `1a7893d`)

Source: [`timokoesters/conduit@1a7893d`](https://github.com/timokoesters/conduit/commit/1a7893d) (2022-10)

## What changed vs step 532

| Rust change | C++ translation |
|---|---|
| Fix: update state_cache on join over federation. State cache update for federation joins. 6 files changed. | **Translated** — Our state cache (step 83) updates on join. This fixes the Rust version. |

## Implementation details

- Our state cache (step 83) updates on join. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
