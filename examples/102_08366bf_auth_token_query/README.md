# Step 102 — "fix: only allow request to pass auth with token query if auth type is None" (Conduit `08366bf`)

Source: [`timokoesters/conduit@08366bf`](https://github.com/timokoesters/conduit/commit/08366bf)

## What changed vs step 101

| Rust change | C++ translation |
|---|---|
| `openid/request_token` enforces that `body.user_id == sender_user` | **Already implemented** at `main.cpp:924-932` — error "requested user ID does not match sender" |
| Ruma wrapper: if AuthScheme != None and token is invalid, return 401 directly (don't fall through to query param) | **Already implemented** — our `extract_token` prefers `Authorization` header over `access_token` query param. If the header is present and is Bearer, the query param is ignored entirely. |

## Implementation status

Both security fixes from 08366bf are already in place in step 101:
1. **openid endpoint** (`main.cpp:925`): explicit check that the URL's `userId` matches the authenticated sender
2. **token resolution** (`handlers.cpp:50-63`): `extract_token` checks `Authorization: Bearer` header first; only falls through to `?access_token=` if no header is present

This is therefore a **no-op step** that documents chronological correspondence to
the Conduit HEAD. The C++ translation was achieved earlier (in step 59 for
openid and step 5 for token resolution) before the corresponding Conduit
commit landed.

## Files changed

None. Step 102 is a copy of step 101 with this README explaining the no-op.

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
