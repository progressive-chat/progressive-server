# Step 280 — "Refactor some canonical JSON code" (Conduit `af6fea3`)

Source: [`timokoesters/conduit@af6fea3`](https://github.com/timokoesters/conduit/commit/af6fea3) (2021-05)

## What changed vs step 279

| Rust change | C++ translation |
|---|---|
| Refactor some canonical JSON code. 2 files changed. | **Translated** — Our canonical JSON is via nlohmann/json sorted keys. This refactors the Rust version. |

## Implementation details

- Our canonical JSON is via nlohmann/json sorted keys. This refactors the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
