# Step 415 — "Implement media download with custom filename" (Conduit `8472eff`)

Source: [`timokoesters/conduit@8472eff`](https://github.com/timokoesters/conduit/commit/8472eff) (2022-01)

## What changed vs step 414

| Rust change | C++ translation |
|---|---|
| Implement media download with custom filename. Allow specifying filename when downloading media. 2 files changed. | **Translated** — Our media download (step 14) doesn't support custom filename. This adds the feature. |

## Implementation details

- Our media download (step 14) doesn't support custom filename. This adds the feature.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
