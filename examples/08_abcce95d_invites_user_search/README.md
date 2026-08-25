# Step 8 — "invites, better public room dir, user search" (Conduit `abcce95d`, 2020-04-14)

Source: [`timokoesters/conduit@abcce95d`](https://github.com/timokoesters/conduit/commit/abcce95d)
— the commit that made Conduit an actual usable chat: invites, room state
tracking, a real public directory and user search.

Folded prerequisites from skipped intermediates (needed context): membership
trees + `createRoom` + per-room sync timelines.

## What changed vs step 7

| Rust change | C++ translation |
|---|---|
| `Data::users_all()` — iterate registered ids | same (`userid_password` keys) |
| token tree `deviceid_token` → `userdeviceid_token` (key = user + 0xff + device); random tokens/devices from ddcd423e folded in | identical layout; `new_token()` = 32 random chars |
| `MultiValue::remove_value(id, value)` | same |
| NEW tree `roomstateid_pdu` ('d'+room+0xff+type+0xff+state_key → pdu); `pdu_append` writes state events into it | identical key layout |
| `room_state(room_id)` — current state | returns raw canonical PDUs |
| `room_invite(sender, room, user)` appends m.room.member invite + `userid_inviteroomids.add`; `rooms_invited` | identical |
| createRoom appends m.room.create/m.room.power_levels (verbatim values)/m.room.name/topic, joins creator, processes `invite` list | `create_room_route` |
| POST /rooms/<id>/invite | `invite_user_route` |
| POST /user_directory/search — substring filter over users | same |
| publicRooms: names from room_state, sorted by num_joined_members desc | same |
| /sync gains invited rooms w/ stripped state (`to_stripped_state_event`) | `stripped_state` → `{content,sender,state_key,type}` projection |
| GET /voip/turnServer & POST /publicised_groups 404 stubs ("There is no turn server yet.") | preserved |

## Verified scenario

```
bob registers, creates "The Matrix" inviting @alice
→ alice's /sync:  @bob:localhost invites @alice:localhost
alice joins (m.room.member join appended)
bob sends message
→ alice's /sync timeline:
   m.room.create        @bob
   m.room.power_levels  @bob
   m.room.name          @bob   "The Matrix"
   m.room.member(invite) @bob
   m.room.member(join)   @alice
   m.room.message        @bob  "wake up neo"
search 'ali'  -> @alice:localhost
publicRooms   -> The Matrix, num_joined_members=2
```

Bugs found while translating (study notes):
1. `random_string` sampled indices 0..63 over a 62-char alphabet — classic OOB
   UB producing NUL bytes inside generated room ids. Fixed with bounded dist.
2. This sandbox serves loopback only cross-process, so the test harness spawns
   the server binary instead of an in-process client.
