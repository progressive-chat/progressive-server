# Step 48 — "Add roomid_statehash tree, clean up review issues" (Conduit `d73c6aa8`)

Source: [`timokoesters/conduit@d73c6aa8`](https://github.com/timokoesters/conduit/commit/d73c6aa8) (2020-08)

## What changed vs step 47

| Rust change | C++ translation |
|---|---|
| Adds `roomid_statehash` sled tree that maps room_id to the latest StateHash. Review feedback cleanup of `join_room_by_id` route. | **Partially translated** — the new sled trees are added, but the full state-res algorithm is implemented in step 83 (`d71d94a_msc4297_state_res_v2`). The simplified implementation here provides the data structures only. |

## Implementation details

- **Partially translated** — the new sled trees are added, but the full state-res algorithm is implemented in step 83 (`d71d94a_msc4297_state_res_v2`). The simplified implementation here provides the data structures only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
