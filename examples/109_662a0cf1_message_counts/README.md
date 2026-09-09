# Step 109 — "improvement: better and more efficient message count calculation" (Conduit `662a0cf1`)

Source: [`timokoesters/conduit@662a0cf1`](https://github.com/timokoesters/conduit/commit/662a0cf1) (2021-04-12)

Covers straight-order intermediates `a8231eef` (alias parsing), `a961732f`
(overflow) and `1dc85895` (invalid-user-id warning), all folded in below.

## What changed vs step 108

| Rust change | C++ translation |
|---|---|
| **New trees `userroomid_notificationcount` / `userroomid_highlightcount`** | **Implemented** — `userroomid_notificationcount`, `userroomid_highlightcount` (user+room → BE u64) + constructor/open wiring |
| **Bump counts on PDU append via push-rule evaluation** | **Implemented** — `pdu_append` resets the sender's counts, then evaluates every other joined member's rules (stored or server-default) and bumps notify/highlight counters |
| **Shared `pusher::get_actions` with real displayname** | **Implemented** — `push_rules::get_actions(user, display_name, rules, event, room)`; `contains_display_name` now prefers the actual displayname (`displayname_get`) with localpart fallback |
| **Sync serves stored counts as `unread_notifications`** | **Implemented** — `SyncResponse::{notification_count, highlight_count}` populated from stored counters and serialized (replaces PDU scans) |
| **`reset_notification_counts` on read markers/receipts + own send** | **Adapted** — `Data::reset_notification_counts` implemented and called on own send; no receipt/read-marker endpoints exist in C++ yet, so no call sites there |
| **Invite state gains sender member event + invite PDU itself** | **Implemented** — local `room_invite` and federation `handle_incoming_invite` both append them |
| **`1dc85895`: warn on invalid user id in send_join response** | **Adapted** — warn + skip the malformed PDU (upstream fails the whole join; simplified flow continues) |
| **`a8231eef`: alias parsing (values are plain strings, not JSON)** | **No-op** — C++ `room_aliases()` already treats `aliasid_alias` values as plain strings |
| **`a961732f`: `saturating_sub` in presence timeout scan** | **No-op** — no presence/EDU code exists in C++ yet |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
