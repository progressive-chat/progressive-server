# Step 2 — "simple endpoint handlers" (Conduit `cd777af4`, 2020-02-18)

Source: [`timokoesters/conduit@cd777af4`](https://github.com/timokoesters/conduit/commit/cd777af41c32cd0aba56b93d0e8fd6c42bc9a3ac)
— the second commit in the lineage.

## Deltas vs step 1

| Rust | C++ |
|---|---|
| 4 new stub routes (versions, get_alias, join, send) | new handlers + `svr.Get/Post/Put` with regex captures for `<placeholders>` |
| `MatrixResult<T>(Result<T, Error>)` responder | `ruma::MatrixResult<T>` = `std::variant<T, Error>` + generic `respond()` |
| `ruma::error::{ErrorKind}` InvalidUsername/NotFound | same errcodes via `errcode()` |
| register builds `UserId` via TryFrom (fails on bad chars) | `localpart_valid()` |
| defaults: token `"randomtoken"`, homeserver `"localhost"`, device `"randomid"` | identical |

## Behavior

```console
$ curl http://127.0.0.1:8000/_matrix/client/versions
{"versions":["r0.6.0"]}

$ curl -d '{"username":"neo"}' -X POST .../r0/register
{"access_token":"randomtoken","device_id":"randomid","home_server":"localhost","user_id":"@neo:localhost"}

$ curl -d '{"username":"bad user!"}' -X POST .../r0/register
{"errcode":"M_INVALID_USERNAME","error":"Username was invalid. "}

$ curl '.../directory/room/%23room:localhost'
{"room_id":"!xclkjvdlfj:localhost","servers":["localhost"]}
```

Still no persistence — every event is `$randomeventid`. That arrives in step 3.
