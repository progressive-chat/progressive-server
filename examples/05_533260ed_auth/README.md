# Step 5 — "Add auth" (Conduit `533260ed`)

Source: [`timokoesters/conduit@533260ed`](https://github.com/timokoesters/conduit/commit/533260ed) (2020-03-29)

## What changed vs step 4

| Rust change | C++ translation |
|---|---|
| Adds bearer-token authentication. New trees: `userdeviceid_token`, `token_userid`, `userid_deviceids`. New endpoints: `/account/register`, `/account/password`, `/login`. M_MISSING_TOKEN and M_UNKNOWN_TOKEN 401 errors. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
