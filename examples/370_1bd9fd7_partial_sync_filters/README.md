# Step 370 — "feat: partially support sync filters" (Conduit `1bd9fd7`)

Source: [`timokoesters/conduit@1bd9fd7`](https://github.com/timokoesters/conduit/commit/1bd9fd7) (2022-01)

## What changed vs step 369

| Rust change | C++ translation |
|---|---|
| Feat: partially support sync filters. /sync filter support for clients. 5 files changed. NEW FEATURE. | **Translated** — Our /sync (step 6) doesn't support filters. This adds partial filter support. |

## Implementation details

- Our /sync (step 6) doesn't support filters. This adds partial filter support.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
