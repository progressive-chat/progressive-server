# Step 793 — media_dir_creation

Source: [`timokoesters/conduit@1f7f74a`](https://github.com/timokoesters/conduit/commit/1f7f74a) (2025-08-28)

## What changed vs step 792

| Rust change | C++ translation |
|---|---|
| Creates the media directory only when a new file is uploaded (not on startup). No-op (we always create on startup). | **Requires media implementation** — Our media handling can be optimized. |

## Implementation details

This fix optimizes media directory creation:

1. **Removed**: `fs::create_dir_all` from `get_media_path` (called on every media access)
2. **Added**: Directory creation only in `create_file` when actually uploading a new file
3. **Only for Deep directory structure**: Only creates parent directories for deep structure

**Status:** Our media implementation (step 83+) may have similar optimization opportunity.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```