# Step 270 — "Refactor usage of CanonicalJsonValue" (Conduit `2e1d7d1`)

Source: [`timokoesters/conduit@2e1d7d1`](https://github.com/timokoesters/conduit/commit/2e1d7d1) (2021-04)

## What changed vs step 269

| Rust change | C++ translation |
|---|---|
| Refactor usage of CanonicalJsonValue. Canonical JSON handling improvements. 4 files changed. | **Translated** — Our canonical JSON is via nlohmann/json sorted keys. This refactors the Rust version. |

## Implementation details

- Our canonical JSON is via nlohmann/json sorted keys. This refactors the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
