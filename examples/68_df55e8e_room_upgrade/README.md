# Step 68 — "Add room upgrade." (Conduit `df55e8e`)

Source: [`timokoesters/conduit@df55e8e`](https://github.com/timokoesters/conduit/commit/df55e8e) (2020-08)

## What changed vs step 67

| Rust change | C++ translation |
|---|---|
| Adds the `POST /rooms/{id}/upgrade` endpoint. Upgrades a room to a new version, tombstones the old room, and transfers state. | **Translated** — our step 25 (`df55e8ed_room_upgrade`) implements this with the full tombstone + predecessor + state transfer logic. |

## Implementation details

- **Translated** — our step 25 (`df55e8ed_room_upgrade`) implements this with the full tombstone + predecessor + state transfer logic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
