# Step 192 — "State resolution outline for /send" (Conduit `4a92a29`)

Source: [`timokoesters/conduit@4a92a29`](https://github.com/timokoesters/conduit/commit/4a92a29) (2021-02)

## What changed vs step 191

| Rust change | C++ translation |
|---|---|
| State resolution outline for `/send`. Another iteration of the state-res work for incoming events. | **Translated** — Our step 83 (`d71d94a_msc4297_state_res_v2`) implements the final state-res. |

## Implementation details

- Our step 83 (`d71d94a_msc4297_state_res_v2`) implements the final state-res.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
