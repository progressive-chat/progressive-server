# Step 810 — "Return proper error in case of invalid UTF-8 in json_body" (Conduit `699f7767`)

Source: [`timokoesters/conduit@699f7767`](https://github.com/timokoesters/conduit/commit/699f7767) (2021-06-30)

Upstream context: `json_body` is used in routes that need authentication.
When an unknown field is set, ruma doesn't parse that field and so reports
no error on invalid UTF-8 — but Conduit had already parsed the raw body, and
on error made `json_body` None. Every UIAA session-creation site then called
`body.json_body.expect("body is json")`, panicking into an internal error.
The fix returns `400 M_NOT_JSON ("Not json.")` instead.

## What changed vs step 809

| Rust change | C++ translation |
|---|---|
| **`register` / `change_password` / `deactivate` / `delete_device(s)` / `upload_signing_keys`: `expect("body is json")` → `if let Some(json)` … `else Err(BadRequest(NotJson, "Not json."))`** | **Implemented at the UIAA session-creation site that exists in this port** — `POST /register` returns `400 {"errcode":"M_NOT_JSON","error":"Not json."}` when the request body is not valid JSON (e.g. invalid UTF-8) instead of creating a session with an empty object |
| **New `ErrorKind::NotJson` usage** | **Added** — `ruma::ErrorKind::NotJson` → `"M_NOT_JSON"` in `src/ruma_wrapper.*` |
| **`device.rs` / `keys.rs` hunks** | **No counterpart yet** — this port has no `DELETE /devices`, `DELETE /devices/:id`, or `POST /keys/upload` client routes, so there is nothing to change there |
| **`change_password` / `deactivate` hunks** | **Already non-panicking** — these routes never stored the raw body (no `uiaa_create` call, no `.expect` equivalent); invalid bodies already fall through to the 401-flows branch, so behavior is unchanged |

Scope note: only the session-creation branch is affected, exactly like
upstream. A valid-JSON body without `auth` still yields `401` + flows; a
valid-JSON body with `auth.type == "m.login.dummy"` still registers.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit131
# invalid UTF-8 body -> 400 M_NOT_JSON (was: 401 + UIAA session)
$ printf '{\xff}' | curl -s -o /dev/null -w '%{http_code}\n' --data-binary @- http://127.0.0.1:8000/_matrix/client/r0/register
400
```
