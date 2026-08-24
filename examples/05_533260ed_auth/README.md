# Step 5 — "Add auth" (Conduit `533260ed`, 2020-03-29)

Source: [`timokoesters/conduit@533260ed`](https://github.com/timokoesters/conduit/commit/533260ed)
— the birth of access tokens and the four-tree auth model that every
descendant (conduwuit, tuwunel, continuwuity) still uses in expanded form.

(Skipped upstream: `744e0adf` "Try to impl auth in ruma_wrapper" was the WIP
that this commit finished.)

## What changed vs step 4

| Rust change | C++ translation |
|---|---|
| tree names become constants: `USERID_PASSWORD`, `USERID_DEVICEIDS`, `DEVICEID_TOKEN`, `TOKEN_USERID` | same four constants in `data.cpp` |
| `utils.rs`: `vec_to_bytes`/`bytes_to_vec` — device lists stored NUL-joined in ONE value | `utils::vec_to_bytes/bytes_to_vec` (`utils.hpp/cpp`) |
| `Data::user_from_token/password_get/device_add/token_replace` | identical methods; `token_replace` removes the old token first |
| `Ruma<T>` grows `pub user_id: Option<UserId>`; extraction resolves `Authorization: Bearer` / `?access_token=` when `METADATA.requires_authentication`; bare 401s on missing/unknown (TODO comments for proper errcodes) | `Ruma<T>::user_id`, per-type `static constexpr bool REQUIRES_AUTH`, `authenticate()` in the dispatcher — errcodes `M_MISSING_TOKEN`/`M_UNKNOWN_TOKEN` filled where upstream still TODO'd |
| register provisions a device + token (`"TODO:randomtoken"` placeholders!) | identical placeholders |
| **login checks passwords at last** — wrong → `M_UNKNOWN` with empty message @403, no account → `M_FORBIDDEN` empty @403 | faithfully reproduced, empty messages included |
| create_message_event requires auth, builds a real `MessageEvent` (sender from token, `origin_server_ts = millis_since_unix_epoch()`), calls `room_event_add` which is **`todo!()`** — sending a message panics Conduit here | we log the event and continue so the demo survives (documented deviation) |

## Behavior

```console
$ curl -d '{"username":"neo","password":"redpill","device_id":"PHONE"}' -X POST .../r0/register
{"access_token":"TODO:randomtoken","device_id":"PHONE","home_server":"localhost","user_id":"@neo:localhost"}

$ curl -d '{"identifier":{"type":"m.id.user","user":"neo"},"password":"redpill"}' -X POST .../r0/login   # ok
{"access_token":"TODO:randomtoken",...}

$ curl -d '{...,"password":"bluepill"}' -X POST .../r0/login    # wrong password
{"errcode":"M_UNKNOWN","error":""} [403]

$ curl -X PUT -H "Authorization: Bearer TODO:randomtoken" -d '{"body":"hi"}' \
    '.../rooms/!r:localhost/send/m.room.message/t1'
{"event_id":"$TODOrandomeventid:localhost"}      # sender resolved from token

$ curl -X PUT '.../rooms/!r:localhost/send/m.room.message/t1'    # no token
{"errcode":"M_MISSING_TOKEN","error":"Missing access token"} [401]
```

## Build & run

```console
$ g++ -std=c++23 -Wall -Wextra *.cpp -o conduit_step05 && ./conduit_step05
# or: cmake -B build -S . && cmake --build build && ./build/conduit_step05
```

## C++ study notes

1. Two-way lookup without SQL: `DEVICEID_TOKEN` + `TOKEN_USERID` are inverse
   indexes over one relation — exactly how KV stores model joins.
2. `static constexpr bool REQUIRES_AUTH` stands in for ruma's
   `Endpoint::METADATA`; the dispatcher's `authenticate()` is your first
   middleware.
3. Compare `extract_token()` with progressive-server's real
   `src/progressive/auth/auth.cpp` — the header/query duality is spec-mandated
   (and deprecated-but-alive).
