# Step 330 — "Getting capabilities requires authentication" (Conduit `dcb5e59`)

Source: [`timokoesters/conduit@dcb5e59`](https://github.com/timokoesters/conduit/commit/dcb5e59) (2021-07)

## What changed vs step 329

| Rust change | C++ translation |
|---|---|
| Getting capabilities requires authentication. /capabilities endpoint now requires auth. | **Translated** — Our /capabilities (step 8) is public. This adds auth requirement. |

## Implementation details

- Our /capabilities (step 8) is public. This adds auth requirement.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
