# Step 690 — "Sliding sync subscriptions, e2ee, to_device messages" (Conduit `d220641`)

Source: [`timokoesters/conduit@d220641`](https://github.com/timokoesters/conduit/commit/d220641) (2023-07)

## What changed vs step 689

| Rust change | C++ translation |
|---|---|
| Sliding sync subscriptions, e2ee, to_device messages. Sliding sync with E2EE and to-device support. 2 files changed. | **Requires step 670/672/689** — Adds subscriptions, E2EE, to-device to sliding sync. |

## Implementation details

This Conduit commit adds to sliding sync (MSC3575):

1. **Subscriptions**: New `subscriptions` field in request for long-polling updates
2. **E2EE support**: Includes `device_lists` with `changed` and `left` device lists
3. **To-device messages**: Includes `to_device` events in response
4. **Account data**: Includes `account_data` in response
5. **Device one-time keys**: Includes `device_one_time_keys_count`
6. **Extensions**: Better handling of `extensions` field
7. **Improved connection handling**: Better `conn_id` management

**Status:** Requires steps 670/672/689 (sliding sync base). This completes the sliding sync v4 implementation per MSC3575.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```