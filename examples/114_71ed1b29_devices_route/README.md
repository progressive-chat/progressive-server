# Step 114 — "feat: /devices route" (Conduit `71ed1b29`)

Source: [`timokoesters/conduit@71ed1b29`](https://github.com/timokoesters/conduit/commit/71ed1b29) (2021-04-21)

Straight-order intermediate `0b918245` (working-email docs fix) is docs-only,
no code change.

## What changed vs step 113

| Rust change | C++ translation |
|---|---|
| **New tree `userid_devicelistversion`, bumped on add/remove/metadata-update** | **Implemented** — `userid_devicelistversion` (user → BE u64) + wiring; bumped in `device_add`, `remove_device`, `remove_device_by_token` (no metadata store to hook the third bump into yet) |
| **`get_devicelist_version(user)` accessor** | **Implemented** — `Data::get_devicelist_version`, nullopt when never changed |
| **Federation `GET /_matrix/federation/v1/user/devices/:userId`** | **Implemented** — `federation::get_user_devices` → `{user_id, stream_id, devices: [{device_id}]}`; per-device keys/display names omitted (no E2EE device metadata/keys store in C++ yet — arrives with E2EE work) |
| **`0b918245`: support email fix** | **Documented** — docs-only upstream, no code change |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
