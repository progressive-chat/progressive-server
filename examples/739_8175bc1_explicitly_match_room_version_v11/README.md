# Step 739 — "Explicitly match RoomVersionId::V11" (Conduit `8175bc1`)

Source: [`timokoesters/conduit@8175bc1`](https://github.com/timokoesters/conduit/commit/8175bc1) (2023-12)

## What changed vs step 738

| Rust change | C++ translation |
|---|---|
| Explicitly match RoomVersionId::V11. Room v11 version matching. 3 files changed. | **Translated** — Follows step 733 (enable room v11). Explicit v11 matching. |

## Implementation details

- Follows step 733 (enable room v11). Explicit v11 matching.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
