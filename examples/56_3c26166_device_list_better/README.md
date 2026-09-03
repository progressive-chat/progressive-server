# Step 56 — "improvement: device list works better" (Conduit `3c26166`)

Source: [`timokoesters/conduit@3c26166`](https://github.com/timokoesters/conduit/commit/3c26166) (2020-08)

## What changed vs step 55

| Rust change | C++ translation |
|---|---|
| Simplifies `device_list_updates` in `/sync` by removing an unnecessary `UserId::try_from` conversion and storing the `user_target_encrypted` result in a variable. | **Translated** — added `Data::room_members(room_id)` to return the list of user_ids in a room, which is the underlying data source the Conduit commit iterates over. |

## Implementation details

- **Added `Data::room_members(room_id)` in `data.hpp`/`data.cpp`** — returns a `std::vector<std::string>` of all user_ids that are members of the given room. This iterates over the existing `roomid_userids` sled tree, the same data structure that `room_users()` (count) and `rooms_joined()` (reverse lookup) use.
- The Conduit commit's sync.rs change simplifies iteration over `db.rooms.room_members(&room_id)`. Our `/sync` route will use this new method when device list tracking is added in a later step.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
