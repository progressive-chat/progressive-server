# Parity Endpoints Inventory — Conduit vs. our server

**Generated:** 2026-08-28
**Baseline:** `examples/60_9db1f5a13c_admin` (HEAD after the auth-events / createRoom parity fixes)
**Purpose:** Planning artifact listing which Matrix/Conduit endpoints we implement
and which are missing, so remaining parity work can be scoped.

> **Methodology note:** Conduit's source could not be fetched in this environment
> (the `matrix-org/conduit` raw paths 404 and the GitHub API is blocked here), so the
> "Conduit side" below is derived from the **Matrix Client-Server API r0/v3** surface
> that Conduit implements plus Conduit's known `/_conduit/admin/*` API. Once network
> access to the Conduit repo is available, replace this with a literal diff of
> `src/client/mod.rs` + `src/server_server/mod.rs` route attributes against our 69 routes.

---

## 1. What we DO implement (69 routes)

### Client-Server (r0/v3)
- `/_matrix/client/versions`
- `/_matrix/client/r0/login` · `/_matrix/client/r0/logout`
- `/_matrix/client/r0/register`
- `/_matrix/client/r0/account/deactivate` · `/_matrix/client/r0/account/password`
- `/_matrix/client/r0/createRoom`
- `/_matrix/client/r0/join/(.+)`
- `/_matrix/client/r0/profile/([^/]+)` · `/_matrix/client/r0/profile/(.+)/displayname`
- `/_matrix/client/r0/directory/room/(.+)` · `/_matrix/client/r0/directory/list/room/(.+)`
- `/_matrix/client/r0/publicRooms`
- `/_matrix/client/r0/user_directory/search`
- `/_matrix/client/r0/user/(.+)/openid/request_token`
- `/_matrix/client/r0/sync`
- `/_matrix/client/r0/rooms/(.+)/event/(.+)` · `/forget` · `/invite` · `/leave`
  · `/members` · `/messages` · `/redact/([^/]+)/([^/]+)` · `/send/(.+)/(.+)`
  · `/state/(.+)` · `/state/(.+?)/([^/]+)` · `/upgrade`
- `/_matrix/client/r0/room_keys/keys` · `/keys/([^/]+)` · `/keys/([^/]+)/([^/]+)`
  · `/version` · `/version/([^/]+)`
- `/_matrix/client/v1/media/config` · `/media/download/(...)` · `/media/thumbnail/(...)`

### Federation (v1)
- `/_matrix/federation/v1/version` · `/event/(.+)` · `/state_ids/(.+)/(.+)`
  · `/backfill/(.+)` · `/publicRooms` · `/query/directory`
  · `/send/(.+)` · `/send_join/(.+)/(.+)` · `/media/download` · `/media/thumbnail`

### Admin (`/_conduit/admin/*`) — now 8 endpoints (expanded in parity Step 4)
- `/_conduit/admin/version`
- `/_conduit/admin/ping`
- `/_conduit/admin/users` · `/_conduit/admin/users/(.+)`
  · `/_conduit/admin/users/(.+)/displayname`
- `/_conduit/admin/register`
- `/_conduit/admin/user/(.+)/deactivate`
- `/_conduit/admin/user/(.+)/password`

---

## 2. Missing Client-Server endpoints (by area)

### Account / identity
- `/_matrix/client/r0/account/whoami`
- `/_matrix/client/r0/account/3pid` · `/account/3pid/add` · `/account/3pid/bind`
- `/_matrix/client/r0/capabilities`

### Devices
- `/_matrix/client/r0/devices` · `/devices/{deviceId}` · `/devices/{deviceId}/update`

### E2EE keys (no `keys/upload|query|claim|change` at all)
- `/_matrix/client/r0/keys/upload` · `/keys/query` · `/keys/claim` · `/keys/change`

### Room membership extras
- `/_matrix/client/r0/rooms/{roomId}/kick` · `/ban` · `/unban` · `/unsubscribe`

### Room read state
- `/_matrix/client/r0/rooms/{roomId}/receipt` · `/typing` · `/read_markers`
- `/_matrix/client/r0/rooms/{roomId}/context` · `/timestamp_to_event`

### Push / notifications
- `/_matrix/client/r0/pushers` · `/pushers/set`
- `/_matrix/client/r0/pushrules` (+ `/pushrules/{scope}/{kind}/{ruleId}` tree)
- `/_matrix/client/r0/notifications`

### User data
- `/_matrix/client/r0/filter` · `/user/{userId}/filter`
- `/_matrix/client/r0/user/{userId}/account_data` · `/user/{userId}/rooms/{roomId}/account_data`

### Presence / profile extras
- `/_matrix/client/r0/presence/{userId}/status`
- `/_matrix/client/r0/profile/{userId}/avatar_url`

### VoIP / groups / search / thirdparty
- `/_matrix/client/r0/voip/turnServer` — **registered but returns 404 stub**
- `/_matrix/client/r0/publicised_groups` — **registered but returns 404 stub**
- `/_matrix/client/r0/search`
- `/_matrix/client/r0/thirdparty/protocols` · `/thirdparty/locations` · `/thirdparty/user`

### Media
- `/_matrix/client/v1/media/upload` · `/v1/media/preview_url`
- legacy `/_matrix/client/r0/media/*` aliases

### Login extras
- `/_matrix/client/r0/login/get_token` (token login) · `/_matrix/client/r0/refresh`
- `/_matrix/client/r0/logout/all`

---

## 3. Missing Admin endpoints (Conduit's `/_conduit/admin/*` is much larger)

We implement 5; Conduit additionally has (non-exhaustive):
- `/_conduit/admin/user/{userId}/activate` (deactivate/password now implemented)
- `/_conduit/admin/user/{userId}/room/{roomId}/...` (per-room admin)
- `/_conduit/admin/room/{roomId}/...` (disable, make_admin, delete, etc.)
- `/_conduit/admin/purge_room` · `/purge_room_cache`
- `/_conduit/admin/reset_password` · `/make_room_admin`
- `/_conduit/admin/ping` · `/relaunch` · `/warn` · `/message`
- `/_conduit/admin/account_validity/...`
- `/_conduit/admin/media/...` · `/server_notices/...` · `/export`

---

## 4. Whole subsystems absent (not just missing routes)

| Subsystem | Status | Notes |
|---|---|---|
| **Application Service API** | absent | `/_matrix/appservice/*`, AS auth, 3PID/ephemeral |
| **Sliding Sync (MSC3575)** | absent | `/_matrix/client/unstable/org.matrix.msc3575/sync` |
| **Spaces (MSC1772/2946)** | partial | Space semantics are mostly state rels; no space-specific UX endpoints |
| **Device + E2EE full** | partial | `room_keys/*` (backup) present; no `keys/*`, no device CRUD |
| **Room-version MSC negotiation** | thin | `/upgrade` exists; supported-version list not driven by MSC feature flags |
| **Push / presence / receipts** | absent | no pushrules, presence, receipts, typing, read_markers |

---

## 5. Known stubs / placeholders (fixed vs. outstanding)

| Item | State |
|---|---|
| `auth_events = ["$auth_eventid"]` | **Fixed** (Step 1): now a computed chain from room state |
| `kPlaceholderToken` / `kPlaceholderDeviceId` | **Removed** (Step 1): were dead code; tokens already random |
| `/voip/turnServer` → 404 | **Outstanding** stub |
| `/publicised_groups` → 404 | **Outstanding** stub |
| `m.room.join_rules` on `createRoom` | **Fixed** (Step 2): now honors `preset` |
| event_id hash excludes `auth_events` | **Outstanding**: hash computed before `auth_events` is set |

---

## 6. Suggested next parity priorities

1. **`/account/whoami` + `/capabilities`** — tiny, high value (clients expect them immediately).
2. **`/keys/upload|query|claim` + `/devices`** — unblocks E2EE-capable clients.
3. **Room admin trio `/kick` `/ban` `/unban`** — reuses existing auth/power-level logic.
4. **Replace the two 404 stubs** (`voip/turnServer`, `publicised_groups`) with real (if minimal) handlers.
5. **Expand `/_conduit/admin/*`** to the commonly-used subset (user deactivate/password, purge_room, make_room_admin).
6. **Subsystems:** appservice → sliding-sync → spaces, in that order per the original expansion plan.
