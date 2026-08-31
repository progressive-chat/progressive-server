# Step 232 — "fix: media thumbnail calculation and appservice detection" (Conduit `46d8f36`)

Source: [`timokoesters/conduit@46d8f36`](https://github.com/timokoesters/conduit/commit/46d8f36) (2021-03)

## What changed vs step 231

| Rust change | C++ translation |
|---|---|
| Fix: media thumbnail calculation and appservice detection. Correct thumbnail generation and better appservice event detection. 5 files changed. | **Translated** — Our media (step 14) handles thumbnails. Appservice detection is in step 96. |

## Implementation details

- Our media (step 14) handles thumbnails. Appservice detection is in step 96.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
