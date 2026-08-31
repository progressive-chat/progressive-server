# Step 247 — "improvement: check signatures on join" (Conduit `5049d0e`)

Source: [`timokoesters/conduit@5049d0e`](https://github.com/timokoesters/conduit/commit/5049d0e) (2021-04)

## What changed vs step 246

| Rust change | C++ translation |
|---|---|
| Improvement: check signatures on join. Verify event signatures when joining a room via federation. | **Translated** — Our join handler (step 25 `d4e2c0c_room_upgrade`) verifies signatures. This adds more checks. |

## Implementation details

- Our join handler (step 25 `d4e2c0c_room_upgrade`) verifies signatures. This adds more checks.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
