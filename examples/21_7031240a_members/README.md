# Step 21 — "improvement: /members route" (Conduit `7031240a`)

Source: [`timokoesters/conduit@7031240a`](https://github.com/timokoesters/conduit/commit/7031240a) (2020-06-16)

## What changed vs step 20

| Rust change | C++ translation |
|---|---|
| `GET /rooms/{id}/members` requires joined membership (returns 403 for non-members). Returns real member events via `room_state_type(RoomMember)` (prefix-scan `roomstateid_pdu` by type). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
