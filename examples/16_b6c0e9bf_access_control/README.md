# Step 16 — "feat: access control" (Conduit `b6c0e9bf`, 2020-05-24, PR #22)

Source: [`timokoesters/conduit@b6c0e9bf`](https://github.com/timokoesters/conduit/commit/b6c0e9bf)

## What changed vs step 15

| Rust change | C++ translation |
|---|---|
| `append_pdu` gains full state-event authorization: power levels from state (defaults ban/kick/redact/invite=50, state_default=0), sender membership+power resolution | auth block at top of `Data::pdu_append`; returns false + stores nothing when rejected |
| complete m.room.member transition matrix: join (self / public / invite rules), invite (sender joined, power≥invite, target not join/ban), leave (self, or kick with power≥kick & target<sender), ban (power≥ban & target<sender) | same rules verbatim |
| `m.room.create` only valid as first event (`prev_events.is_empty()`) | identical |
| other state events require joined + power≥state_default; message events require joined membership | identical; non-member rejection returns 403 M_FORBIDDEN |
| membership tree maintenance moved into `update_membership` called post-authorization from append_pdu | `Data::update_membership` — join/invite/left trees maintained in one place |

## Verified

```
alice msg without joining        → 403 event not authorized
alice joins public room          → 200
alice msg after joining          → 200
bob bans alice                   → 200
banned alice sends               → 403
banned alice re-joins            → 403
```

## Study notes

Two upstream bugs reproduced and fixed here:
1. At this commit upstream appended power_levels BEFORE the creator joined,
   so the PL event failed its own auth check — they blacklisted the failing
   test instead. We fix it properly: creator joins right after m.room.create.
2. An argument swap in update_membership(room_id, user_id, membership) made
   bans silently no-op — caught by scenario test 5.
