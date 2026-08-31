# Step 452 — "Clean up error handling for server_server::get_server_keys_route" (Conduit `d1d2217`)

Source: [`timokoesters/conduit@d1d2217`](https://github.com/timokoesters/conduit/commit/d1d2217) (2022-02)

## What changed vs step 451

| Rust change | C++ translation |
|---|---|
| Clean up error handling for server_server::get_server_keys_route. Error handling improvement for key fetching. 1 file changed. | **Translated** — Our key fetching (step 8) has error handling. This cleans up the Rust version. |

## Implementation details

- Our key fetching (step 8) has error handling. This cleans up the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
