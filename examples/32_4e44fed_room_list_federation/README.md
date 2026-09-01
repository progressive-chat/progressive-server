# Step 32 — "fix: room list over federation" (Conduit `4e44fed`)

Source: [`timokoesters/conduit@4e44fed`](https://github.com/timokoesters/conduit/commit/4e44fed) (2020-09-14)

## What changed vs step 31

| Rust change | C++ translation |
|---|---|
| **`get_public_rooms_filtered`** federation endpoint added | **Translated** — Added `get_public_rooms_filtered_route` federation endpoint |
| **`get_public_rooms_filtered_helper`** takes proper filter and room_network parameters | **Translated** — Updated `get_public_rooms_filtered_helper` to accept filter and room_network |
| **`get_public_rooms_route`** uses `IncomingFilter::default()` and `IncomingRoomNetwork::Matrix` | **Translated** — Updated route to use default filter and Matrix room network |
| **`get_public_rooms_filtered`** federation endpoint returns `get_public_rooms_filtered::v1::Response` | **Translated** — Added conversion from federation to client-server response types |

## Implementation details

- **New federation endpoint**: `GET /_matrix/federation/v1/publicRooms` with `get_public_rooms_filtered::v1::Request` body
- **Updated `get_public_rooms_filtered_helper`**: Now takes `&IncomingFilter` and `&IncomingRoomNetwork` parameters
- **Updated `get_public_rooms_route`**: Uses `IncomingFilter::default()` and `IncomingRoomNetwork::Matrix`
- **Response conversion**: Converts federation `PublicRoomsChunk` to client-server format via JSON serialization

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
