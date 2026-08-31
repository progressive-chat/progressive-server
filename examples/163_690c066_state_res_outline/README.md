# Step 163 — "State resolution outline for /send" (Conduit `690c066`)

Source: [`timokoesters/conduit@690c066`](https://github.com/timokoesters/conduit/commit/690c066) (2021-01)

## What changed vs step 162

| Rust change | C++ translation |
|---|---|
| State resolution outline for `/send`. The first commit of the new state-res work for incoming PDU validation. | **Translated** — Our step 83 (`d71d94a_msc4297_state_res_v2`) implements the state resolution for incoming events. |

## Implementation details

- Our step 83 (`d71d94a_msc4297_state_res_v2`) implements the state resolution for incoming events.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
