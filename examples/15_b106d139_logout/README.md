# Step 15 — "Add logout route and database methods (#21)" (Conduit `b106d139`)

Source: [`timokoesters/conduit@b106d139`](https://github.com/timokoesters/conduit/commit/b106d139) (2020-05-24)

## What changed vs step 14

| Rust change | C++ translation |
|---|---|
| Adds `POST /_matrix/client/r0/logout` which calls `Data::remove_device_by_token`. Removes the device's token binding, the reverse `token_userid` entry, and the device from `userid_deviceids`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
