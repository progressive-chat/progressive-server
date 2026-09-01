# Step 735 — "Return error instead of panic when first event is not m.room.create" (Conduit `5a7bb1e`)

Source: [`timokoesters/conduit@5a7bb1e`](https://github.com/timokoesters/conduit/commit/5a7bb1e) (2023-12)

## What changed vs step 734

| Rust change | C++ translation |
|---|---|
| Return error instead of panic when first event is not m.room.create. Handle missing create event gracefully. 2 files changed. | **Translated** — Our room create (step 10) expects create event. This adds error instead of panic. |

## Implementation details

- Our room create (step 10) expects create event. This adds error instead of panic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
