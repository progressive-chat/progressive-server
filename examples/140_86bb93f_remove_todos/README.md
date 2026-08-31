# Step 140 — "Remove outdated TODOs, use StateEvent::from_id_value consistently" (Conduit `86bb93f`)

Source: [`timokoesters/conduit@86bb93f`](https://github.com/timokoesters/conduit/commit/86bb93f) (2020-12)

## What changed vs step 139

| Rust change | C++ translation |
|---|---|
| Remove outdated TODOs, use `StateEvent::from_id_value` consistently. | **No-op for us** — Our state-res implementation is in step 83 (`d71d94a_msc4297_state_res_v2`) which doesn't have these TODOs. |

## Implementation details

- Our state-res implementation is in step 83 (`d71d94a_msc4297_state_res_v2`) which doesn't have these TODOs.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
