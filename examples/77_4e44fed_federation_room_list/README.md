# Step 77 — "fix: room list over federation" (Conduit `4e44fed`)

Source: [`timokoesters/conduit@4e44fed`](https://github.com/timokoesters/conduit/commit/4e44fed) (2020-09)

## What changed vs step 76

| Rust change | C++ translation |
|---|---|
| Adds the `/_matrix/federation/v1/publicRooms` endpoint for serving our public rooms to peer servers. | Our step 32 (`4e44fedbc_fed_publicrooms`) implements this endpoint. |

## Implementation details

- Our step 32 (`4e44fedbc_fed_publicrooms`) implements this endpoint.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
