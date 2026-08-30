# Step 16 — "feat: access control" (Conduit `b6c0e9bf`)

Source: [`timokoesters/conduit@b6c0e9bf`](https://github.com/timokoesters/conduit/commit/b6c0e9bf) (2020-05-25)

## What changed vs step 15

| Rust change | C++ translation |
|---|---|
| Major access-control refactor. `Data::pdu_append` gains full state-event authorization: power levels from state, sender membership+power resolution, complete m.room.member transition matrix (join/invite/leave/ban/kick). `Data::update_membership` maintains the membership trees. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
