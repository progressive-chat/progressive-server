# Step 116 — "feat: send invites over federation" (Conduit `58463bba`)

Source: [`timokoesters/conduit@58463bba`](https://github.com/timokoesters/conduit/commit/58463bba) (2021-04-25)

Straight-order intermediates with no C++ behavior change: `6e84d317`
(ruma-version type churn), `bb234ca0` (typing dedup — no EDU code here),
`7067d7ac` (Responder flatten), `e72fd44b` (appservice error flatten),
`2fc1ec2a` (rocket rev bump).

## What changed vs step 115

| Rust change | C++ translation |
|---|---|
| **`invite_helper` (remote-capable invites)** | **Implemented** — `invite_helper()` in `main.cpp`: remote targets get a built, signed invite PDU sent to their server's v1 `/invite`; the returned signed event is stored + fanned out; locals use the existing path |
| **Remote PDU: prev cap 20, depth, auth placeholder, prev_content, sign** | **Implemented** — read-only leaves, max-depth+1, `["$auth_eventid"]` placeholder (as in `pdu_append`), `unsigned.prev_content`, `hash_and_sign_event` (real sigs since step 115) |
| **Invite state via `calculate_invite_state`** | **Already matched** — `build_invite_state` + sender member + invite event (steps 108/109); reused for the outgoing send |
| **Local invite content: displayname/avatar/is_direct** | **Implemented** — target displayname + `is_direct` flag (`avatar_url` has no store here yet); `room_invite` grew an `is_direct` param |
| **createRoom/invite routes use helper, ignore per-invite errors** | **Implemented** — `is_direct` parsed on createRoom; `let _ =` semantics kept |
| **Profile broadcasts ignore per-room failures** | **Implemented** — `displayname_set` now covers all joined rooms instead of returning after the first |
| **`handle_incoming_pdu` made public** | **Documented** — no such function in C++; incoming handling lives in `handle_incoming_invite`/`fetch_and_handle_events` |
| **`226045ea`: '@' reverse-proxy warning on verify failure** | **Implemented** — in the federation verifier |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
