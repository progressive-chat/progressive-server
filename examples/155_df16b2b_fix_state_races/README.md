# Step 155 — "fix: rare state races" (Conduit `df16b2b`)

Source: [`timokoesters/conduit@df16b2b`](https://github.com/timokoesters/conduit/commit/df16b2b) (2020-12)

## What changed vs step 154

| Rust change | C++ translation |
|---|---|
| Fix: rare state races. Adds proper locking when accessing shared state during state resolution. | **Translated** — Our sled adapter uses internal locking. The state resolution itself is in step 83 (`d71d94a_msc4297_state_res_v2`). |

## Implementation details

- Our sled adapter uses internal locking. The state resolution itself is in step 83 (`d71d94a_msc4297_state_res_v2`).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
