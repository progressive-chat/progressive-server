# Step 352 — "feat: support room version 5" (Conduit `918df9c`)

Source: [`timokoesters/conduit@918df9c`](https://github.com/timokoesters/conduit/commit/918df9c) (2021-07)

## What changed vs step 351

| Rust change | C++ translation |
|---|---|
| Feat: support room version 5. New room version with updated algorithms. 6 files changed. | **Translated** — Our room versions (steps 80-87) support v1-v4. v5 adds new features. |

## Implementation details

- Our room versions (steps 80-87) support v1-v4. v5 adds new features.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
