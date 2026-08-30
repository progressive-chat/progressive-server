# Step 13 — "forget rooms, load history" (Conduit `23cb550d`)

Source: [`timokoesters/conduit@23cb550d`](https://github.com/timokoesters/conduit/commit/23cb550d) (2020-04-29)

## What changed vs step 12

| Rust change | C++ translation |
|---|---|
| Adds `POST /rooms/{id}/forget` (`Data::room_forget`) and `GET /rooms/{id}/messages` (`Data::pdus_until`). /sync sets `prev_batch` from the `since` cursor. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
