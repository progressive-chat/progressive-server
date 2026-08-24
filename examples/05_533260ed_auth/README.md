# Step 5 — "Add auth" (Conduit `533260ed`, 2020-03-29)

Source: [`timokoesters/conduit@533260ed`](https://github.com/timokoesters/conduit/commit/533260ed)
— access tokens + the four-tree auth model every descendant still uses.

## Deltas vs step 4

| Rust | C++ |
|---|---|
| trees become constants: `userid_password`, `userid_deviceids` (NUL-joined lists via utils), `deviceid_token`, `token_userid` | identical constants in `data.cpp`; NUL-join helpers in `utils.*` |
| `Data::user_from_token/password_get/device_add/token_replace` | identical |
| `Ruma<T>.user_id: Option<UserId>` resolved from `Authorization: Bearer` / `?access_token=` when `METADATA.requires_authentication`; bare 401s (TODO errcodes upstream) | `REQUIRES_AUTH` flag + `extract_token()`; we emit proper `M_MISSING_TOKEN`/`M_UNKNOWN_TOKEN` where upstream TODO'd |
| register/login provision devices+tokens — literal placeholders `"TODO:randomtoken"` / `"TODO:randomdeviceid"` | kept verbatim |
| login checks passwords at last: wrong → `M_UNKNOWN` "" @403, no account → `M_FORBIDDEN` "" @403 | reproduced including empty messages |

## Verified behavior

```console
$ curl -H "Authorization: Bearer TODO:randomtoken" -d '{...}' -X PUT .../send/m.room.message/t1
{"event_id":"$TODOrandomeventid"}
$ curl -X PUT .../send/...        # no token -> 401 M_UNKNOWN_TOKEN
```
