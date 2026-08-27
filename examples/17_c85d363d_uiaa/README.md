# Step 17 — "feat: user interactive authentication" (Conduit `c85d363d`, 2020-06-06)

Source: [`timokoesters/conduit@c85d363d`](https://github.com/timokoesters/conduit/commit/c85d363d)

## What changed vs step 16

| Rust change | C++ translation |
|---|---|
| new `database/uiaa.rs`: `Uiaa { userdeviceid_uiaainfo: Tree }` — key = user + 0xff + device | `stubdb/database::Uiaa` over the same tree name (`src/uiaa.hpp/cpp`) |
| `create(user, device, uiaainfo)` — start a session | identical |
| `try_auth(...) -> (bool, UiaaInfo)` — resume by session token, complete stage (`m.login.dummy` / `m.login.password` with Argon2id verify), check flows, remove session on success | `Uiaa::try_auth` — dummy implemented; password variant arrives with delete_device (upstream panics on unsupported types; we return a failed attempt) |
| register_route: no auth → store session, 401 with `{flows, session}`; auth present → try_auth, proceed on success | same wire shape: `401 {completed:[],flows:[{stages:["m.login.dummy"]}],params:{},session:<256 chars>}` |

## Verified

```
1) POST /register {"username","password"}            → 401 + flows + session
2) POST /register {...,"auth":{"type":"m.login.dummy","session":…}}
                                                      → 200 full registration
```

This closes the gap noted in step 7: real clients now complete the dummy
flow exactly like against upstream Conduit.
