# Step 101 — "fix: don't ignore content of membership template" (Conduit `3469132`)

Source: [`timokoesters/conduit@3469132`](https://github.com/timokoesters/conduit/commit/3469132)

## What changed vs step 100

| Rust change | C++ translation |
|---|---|
| `populate_membership_template` preserves custom content fields from the received template instead of replacing them entirely | **No-op** — we don't have a `populate_membership_template` helper; our local leave/join/invite/knock events build content from scratch. The security concern this commit addresses (ignoring custom fields that could carry unexpected state) doesn't apply to our local flow. |
| The `join_authorised_via_users_server` field is preserved as part of the content object | **Not applicable** — we don't implement restricted join federation. |

## Implementation status

This is a **no-op step** that preserves chronological correspondence to the
Conduit timeline. The commit modifies Conduit's federation `populate_membership_template`
helper, which we don't have because we don't implement federation
`/make_leave` / `/send_leave` / `/send_join` content preservation.

For our local leave/join/invite/knock flow, content is always built from
the local user profile + the supplied `reason`, so there is no "ignored
content" issue to fix.

## Files changed

None. Step 101 is a copy of step 100 with this README explaining the no-op.

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
