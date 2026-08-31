# Step 51 — "Add helper function for get_alias route" (Conduit `5ccdd369`)

Source: [`timokoesters/conduit@5ccdd369`](https://github.com/timokoesters/conduit/commit/5ccdd369) (2020-08)

## What changed vs step 50

| Rust change | C++ translation |
|---|---|
| Extracts `get_alias_helper` from `get_alias_route` so it can be reused by other routes (notably `join_room_by_id_or_alias`). | **No-op for us** — our C++ code already covers this functionality (see earlier steps). |

## Implementation details

- **No-op for us** — our C++ code already covers this functionality (see earlier steps).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
