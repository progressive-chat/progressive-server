# Step 62 — "fix: clarify that 3pids are currently unsupported" (Conduit `59d7674`, 2024-05-29)

Source: [`timokoesters/conduit@59d7674`](https://github.com/timokoesters/conduit/commit/59d7674)

## What changed vs step 61

| Rust change | C++ translation |
|---|---|
| `request_3pid_management_token_via_email_route` / `..._via_msisdn_route` return `ThreepidDenied` with a clearer message ("Third party identifiers are currently unsupported by this server implementation") | Two new routes `POST /_matrix/client/r0/account/3pid/email/requestToken` and `.../msisdn/requestToken` return `M_THREEPID_DENIED` (HTTP 400) with that message. |

| Rust change | C++ translation |
|---|---|
| `GET /rooms/<id>/event/<event_id>` — joined membership required, returns the raw stored PDU; missing → M_NOT_FOUND "Event not found." | identical, via existing `Data::pdu_get` (eventid_pduid → pduid_pdus lookup from step 6) |

## Verified

```
joined user GET event   → 200 full signed PDU JSON
non-member GET event    → 403 You don't have permission
nonexistent event       → 404 M_NOT_FOUND
```
