# Step 7 — "feat: invites, better public room dir, user search" (Conduit `abcce95d`)

Source: [`timokoesters/conduit@abcce95d`](https://github.com/timokoesters/conduit/commit/abcce95d) (2020-04-14)

## What changed vs step 7

| Rust change | C++ translation |
|---|---|
| Adds `POST /rooms/{id}/invite`, `POST /user_directory/search`, and improves `publicRooms` to read room names from state and sort by members count. /sync gains invited rooms with stripped state. `GET /voip/turnServer` and `POST /publicised_groups` are 404 stubs. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
