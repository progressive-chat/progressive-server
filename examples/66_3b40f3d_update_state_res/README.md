# Step 66 — "Update state-res crate" (Conduit `3b40f3d`)

Source: [`timokoesters/conduit@3b40f3d`](https://github.com/timokoesters/conduit/commit/3b40f3d) (2020-08)

## What changed vs step 65

| Rust change | C++ translation |
|---|---|
| Updates the state-res crate to a new commit. Mostly dependency updates. | **Skipped** — the state-res crate in our C++ is implemented in step 83 (`d71d94a_msc4297_state_res_v2`). |

## Implementation details

- **Skipped** — the state-res crate in our C++ is implemented in step 83 (`d71d94a_msc4297_state_res_v2`).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
