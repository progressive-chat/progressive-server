# Step 31 — "improvement: try out multiple servers when joining remote rooms" (Conduit `c5313b3`)

Source: [`timokoesters/conduit@c5313b3`](https://github.com/timokoesters/conduit/commit/c5313b3) (2020-09-14)

## What changed vs step 30

| Rust change | C++ translation |
|---|---|
| **`get_alias_helper`** returns `GetAliasResponse` with `servers` field; for remote aliases, queries the remote server | **Translated** — Updated `get_alias_route` to handle remote aliases and return multiple servers |
| **`join_room_by_id_or_alias_route`** handles both room ID and room alias; gets servers from alias response | **Translated** — Added `join_room_by_id_or_alias_route` that accepts both room ID and alias, resolves servers from alias |
| **`join_room_by_id_helper`** tries multiple servers when joining remote rooms | **Translated** — Added `send_join_request` that iterates through servers, `join_room_by_id_or_alias_route` uses it |
| **`send_request`** takes `&ServerName` instead of `String` | **Translated** — Updated `send_request` to handle server names properly |
| **Alias resolution** returns multiple servers | **Translated** — Added `resolve_alias_servers` to get list of servers from alias |

## Implementation details

- **`get_alias_route`**: Enhanced to handle remote aliases (e.g., `#room:server`) by returning the remote server as a potential server
- **`resolve_alias_servers`**: New function to resolve a room alias to a room ID and list of servers
- **`send_join_request`**: New function that iterates through servers and tries each until one succeeds
- **`join_room_by_id_or_alias_route`**: New endpoint that handles both room ID and room alias, resolves servers from alias, and tries each server
- **`join_room_by_id_or_alias` HTTP route**: Added `POST /_matrix/client/r0/join/{roomIdOrAlias}` endpoint

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
