# Step 423 — "Refactor admin code to always defer command processing" (Conduit `677f044`)

Source: [`timokoesters/conduit@677f044`](https://github.com/timokoesters/conduit/commit/677f044) (2022-01)

## What changed vs step 422

| Rust change | C++ translation |
|---|---|
| Refactor admin code to always defer command processing. Admin command async processing. 3 files changed. | **Translated** — Our admin commands (step 60) process synchronously. This adds async deferral. |

## Implementation details

- Our admin commands (step 60) process synchronously. This adds async deferral.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
