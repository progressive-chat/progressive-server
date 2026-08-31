# Step 424 — "add error handling for register_appservice too" (Conduit `78502aa`)

Source: [`timokoesters/conduit@78502aa`](https://github.com/timokoesters/conduit/commit/78502aa) (2022-01)

## What changed vs step 423

| Rust change | C++ translation |
|---|---|
| Add error handling for register_appservice too. Better error responses for appservice registration. 2 files changed. | **Translated** — Our appservice registration (step 96) has error handling. This improves the Rust version. |

## Implementation details

- Our appservice registration (step 96) has error handling. This improves the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
