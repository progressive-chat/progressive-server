# Step 50 — "Helper for join_room_by_id route so routes aren't calling routes" (Conduit `ea200324`)

Source: [`timokoesters/conduit@ea200324`](https://github.com/timokoesters/conduit/commit/ea200324) (2020-08)

## What changed vs step 49

| Rust change | C++ translation |
|---|---|
| Extracts `join_room_by_id_helper` function so the route no longer calls another route (which caused panics). | **No-op for us** — our C++ code already covers this functionality (see earlier steps). |

## Implementation details

- **No-op for us** — our C++ code already covers this functionality (see earlier steps).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
