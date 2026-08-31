# Step 329 — "Return proper error in case of invalid UTF-8 in json_body" (Conduit `699f776`)

Source: [`timokoesters/conduit@699f776`](https://github.com/timokoesters/conduit/commit/699f776) (2021-07)

## What changed vs step 328

| Rust change | C++ translation |
|---|---|
| Return proper error in case of invalid UTF-8 in json_body. Better JSON parsing error handling. | **Translated** — Our JSON parsing (nlohmann/json) handles UTF-8. This ensures proper error on invalid input. |

## Implementation details

- Our JSON parsing (nlohmann/json) handles UTF-8. This ensures proper error on invalid input.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
