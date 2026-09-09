# Step 107 — "Upgrade ruma with push rules refactoring" (Conduit `fe744c85`)

Source: [`timokoesters/conduit@fe744c85`](https://github.com/timokoesters/conduit/commit/fe744c85) (2021-04-05)

## What changed vs step 106

| Rust change | C++ translation |
|---|---|
| **Upgrade ruma, refactor push.rs to `.get()`/`.replace()`** | **Implemented** — `PUT/GET/DELETE /pushrules/<scope>/<kind>/<ruleId>` use replace/get/remove semantics; added `/actions` and `/enabled` sub-routes |
| **Refactor `pusher.rs` `send_push_notice` to `Ruleset::get_actions`** | **Implemented** — `push_rules::evaluate_push_rules` with `PushConditionRoomCtx` semantics: dotted `content.msgtype` keys, `contains_display_name`, `m.notice` suppression |
| **Delete `src/push_rules.rs` (use ruma `Ruleset`)** | **Adapted** — Kept C++ `push_rules.hpp/.cpp` (no ruma in C++): `PushRuleSet`, `parse_push_rules`, `get_default_push_rules`, `evaluate_push_rules` |
| **Avatar URL type `String` → `MxcUri`** | **Documented** — C++ uses `string` throughout, no change needed |
| **State routes `send_state_event_for_key` merge** | **Documented** — Existing state routes already cover merged API |
| **ruma_wrapper `OutgoingRequest` bound removal** | **Documented** — C++ wrapper has no such bound |

## Implementation details

1. **Database** — `database.hpp/.cpp`: `user_push_rules` (user → ruleset JSON), `user_pusher` (user+pushkey → pusher JSON), `pusher_userid` (pushkey → user) trees + constructor/open wiring (correct order).
2. **Data** — `data.hpp/.cpp`: `set/get_push_rules`, `add/get/get_pushers/remove_pusher`, `set/get_room_account_data`, `pdu_shortstatehash`/`state_full_ids`.
3. **Push rules logic** — `push_rules.hpp/.cpp`: `PushRule`/`PushRuleSet`/`Pusher`, default rules (`.m.rule.master` disabled, `suppress_notices` matches `content.msgtype=m.notice`), dotted-key `event_match`, `get_actions`-style `evaluate_push_rules`.
4. **Endpoints** — `main.cpp`: `GET /pushrules`, `PUT/GET/DELETE /pushrules/<scope>/<kind>/<ruleId>` (scope must be `global`), `GET/PUT .../actions`, `GET/PUT .../enabled`, `POST /pushers/set` (null `kind` = delete), `GET/DELETE /pushers`.
5. **Room account data** — `PUT/GET /user/<user>/rooms/<room>/account_data/<type>` (own data only).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
$ ./build/tests
```
