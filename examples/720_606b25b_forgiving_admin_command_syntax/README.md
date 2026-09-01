# Step 720 — "improvement: more forgiving admin command syntax" (Conduit `606b25b`)

Source: [`timokoesters/conduit@606b25b`](https://github.com/timokoesters/conduit/commit/606b25b) (2023-08)

## What changed vs step 719

| Rust change | C++ translation |
|---|---|
| Improvement: more forgiving admin command syntax. Admin command parser improvements. 2 files changed. | **Translated** — Our admin commands (step 60, 702) parse strictly. This adds flexibility. |

## Implementation details

- Our admin commands (step 60, 702) parse strictly. This adds flexibility.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
