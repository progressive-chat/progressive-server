# Step 35 — "fix: send to all servers and fix media store" (Conduit `71500b1`)

Source: [`timokoesters/conduit@71500b1`](https://github.com/timokoesters/conduit/commit/71500b1) (2020-09-15)

## What changed vs step 34

| Rust change | C++ translation |
|---|---|
| **Media store fix**: `get_content_route` uses `body.server_name`/`body.media_id` directly for MXC | **Translated** — Updated media download to use server_name/media_id from request |
| **Thumbnail fix**: Similar media ID handling for thumbnails | **Translated** — Updated thumbnail route |
| **Remote media fetch**: Only fetches remote if server_name != local server | **Translated** — Updated condition for remote fetch |
| **Send to all servers**: `append_pdu` now iterates over `room_servers` and sends to all | **Translated** — Updated `append_pdu` to send to all room servers |
| **Transaction handling**: Uses futures to send to all servers concurrently | **Translated** — Added concurrent federation sending |
| **Various .to_owned()/.clone() fixes** | **Translated** — Updated parameter passing |

## Implementation details

1. **Media store fixes**:
   - `get_content_route` uses `body.server_name`/`body.media_id` for MXC
   - Only fetches remote if server_name != local server
   - Removed random MXC generation, uses actual server_name/media_id

2. **Federation sending**:
   - `append_pdu` now iterates over `room_servers` and sends to all servers concurrently
   - Uses futures for concurrent sending
   - Proper error handling with warnings

3. **Various parameter fixes**: `.to_owned()`, `.clone()` added where needed

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
