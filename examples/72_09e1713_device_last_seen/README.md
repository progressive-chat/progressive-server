# Step 72 — "feat(devices): update the device last seen timestamp on usage" (Conduit `09e1713`)

Source: [`timokoesters/conduit@09e1713`](https://github.com/timokoesters/conduit/commit/09e1713) (2025-06-06)

## What changed vs step 71

| Rust change | C++ translation |
|---|---|
| Updates `userdeviceid_lastseen` tree on every authenticated request; adds `GET /_matrix/client/v1/devices` to list. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
