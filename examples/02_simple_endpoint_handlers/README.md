# Step 2 — "simple endpoint handlers" (Conduit `cd777af4`, 2020-02-18)

Source: [`timokoesters/conduit@cd777af4`](https://github.com/timokoesters/conduit/commit/cd777af41c32cd0aba56b93d0e8fd6c42bc9a3ac)
— the second commit ever in the Conduit/conduwuit/tuwunel line.

## What changed vs step 1

| Rust change | C++ translation |
|---|---|
| 4 new stub routes (`versions`, `get_alias`, `join_room_by_id`, `create_message_event`) | new handler functions + entries in the dispatch chain |
| Rocket `<placeholder>` route params | `match_route()` splits pattern/path on `/`, captures `<name>` segments, percent-decodes them |
| `MatrixResult<T>(Result<T, Error>)` responder | `ruma::MatrixResult<T>` wrapping `std::variant<T, Error>` + shared `respond()` |
| `ruma::error::{Error, ErrorKind}` | `ruma::Error{kind, message, status_code}`, `errcode()` → `"M_INVALID_USERNAME"` / `"M_NOT_FOUND"` |
| register builds `UserId` via `TryFrom` (fails on bad chars) | `user_id_from_localpart()` validates `[a-z0-9._=/+-]+` and returns bool |
| `body.username.unwrap_or("randomname")` | `body.username.value_or("randomname")` |
| defaults changed: token `"randomtoken"`, homeserver `"localhost"`, device `"randomid"` | same values |

## Behavior

```console
$ curl http://127.0.0.1:8000/_matrix/client/versions
{"versions":["r0.6.0"]}

$ curl -d '{"username":"neo"}' -X POST http://127.0.0.1:8000/_matrix/client/r0/register
{"access_token":"randomtoken","device_id":"randomid","home_server":"localhost","user_id":"@neo:localhost"}

$ curl -d '{"username":"bad user!"}' -X POST http://127.0.0.1:8000/_matrix/client/r0/register
{"errcode":"M_INVALID_USERNAME","error":"Username was invalid. "}

$ curl 'http://127.0.0.1:8000/_matrix/client/r0/directory/room/%23room:localhost'
{"room_id":"!xclkjvdlfj:localhost","servers":["localhost"]}

$ curl 'http://127.0.0.1:8000/_matrix/client/r0/directory/room/%23nope:localhost'
{"errcode":"M_NOT_FOUND","error":"Room not found."}

$ curl -d '{}' -X POST 'http://127.0.0.1:8000/_matrix/client/r0/rooms/!x:localhost/join'
{"room_id":"!x:localhost"}

$ curl -d '{"msgtype":"m.text","body":"hi"}' -X PUT \
    'http://127.0.0.1:8000/_matrix/client/r0/rooms/!x:localhost/send/m.room.message/t1'
{"event_id":"$randomeventid"}
```

Still no persistence — every room is `!xclkjvdlfj:localhost` and every event is
`$randomeventid`. The next commit (`c2c18b46`, "feat: database") replaces that.

## Build & run

```console
$ cmake -B build -S . && cmake --build build && ./build/conduit_step02
# or:
$ g++ -std=c++23 -Wall -Wextra -Wpedantic main.cpp ruma_wrapper.cpp -o conduit_step02
```

## C++ study notes

1. `std::variant<T, Error>` + index checks = a Result type without exceptions.
2. Route params force you to think about ownership: captured strings move from
   the match map into request structs.
3. The dispatch if/else chain is exactly what a router framework generates —
   compare with `src/progressive/http/router.cpp` in this repo (regex-based)
   and with Beast's `router.hpp` examples.
