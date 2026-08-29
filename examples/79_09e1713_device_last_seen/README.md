# Step 79 — "feat(devices): update the device last seen timestamp on usage" (Conduit `09e1713`)

Source: [`timokoesters/conduit@09e1713`](https://github.com/timokoesters/conduit/commit/09e1713)

This step tracks **when a device was last used**. Every authenticated request (sync, devices,
keys upload) updates the device's last-seen timestamp; `GET /devices` exposes it as
`last_seen_ts`.

## What changed vs step 78

| Rust change | C++ translation |
|---|---|
| `userdeviceid_metadata` gains `Device::last_seen_ts` | new tree `userdeviceid_lastseen` (`user + 0xff + device` -> ms) |
| `users::Service` caches `device_last_seen` and flushes to DB every 5 min | `Data::device_last_seen_update` writes through to the tree + in-memory `device_last_seen_cache_` (fresh reads, same observable result) |
| `find_from_token` returns `OwnedDeviceId` | already did via `device_from_token` |
| sync/device/keys routes spawn `update_device_last_seen` | `/sync` route calls `device_last_seen_update(user, device)` (synchronous) |
| `GET /devices` returns `last_seen_ts` | new `GET /_matrix/client/r0/devices` route listing the user's devices with optional `last_seen_ts` |

## Smoke test

```
POST /_matrix/client/r0/register   (device: hBmfpgwh0L)
GET /_matrix/client/r0/devices     -> {"devices":[{"device_id":"hBmfpgwh0L"}]}
GET /_matrix/client/r0/sync
GET /_matrix/client/r0/devices     -> {"devices":[{"device_id":"hBmfpgwh0L","last_seen_ts":1788022248129}]}
GET /_matrix/client/r0/devices (no token) -> 401
```
