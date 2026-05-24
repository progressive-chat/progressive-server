# Progressive Server API Reference

## Protocols

| Protocol | Port | Transport | Status |
|----------|------|-----------|--------|
| Matrix   | 8008 | HTTP      | Full C-S + Federation |
| IRC      | 6667 | TCP       | RFC 1459 + IRCv3 |
| XMPP     | 5222 | TCP/TLS   | RFC 6120 + Extensions |
| Lemmy    | 8008 | HTTP      | REST + ActivityPub |

---

## Matrix Client-Server API (/_matrix/client/v3/)

### /.well-known/matrix/

| Method | Path |
|--------|------|
| GET | `/.well-known/matrix/client` |

### /_matrix/federation/

| Method | Path |
|--------|------|
| GET | `/_matrix/federation/v1/backfill/{roomId}` |
| GET | `/_matrix/federation/v1/event/{eventId}` |
| GET | `/_matrix/federation/v1/event_auth/{roomId}/{eventId}` |
| GET | `/_matrix/federation/v1/make_join/{roomId}/{userId}` |
| GET | `/_matrix/federation/v1/make_leave/{roomId}/{userId}` |
| GET | `/_matrix/federation/v1/media/download/{mediaId}` |
| GET | `/_matrix/federation/v1/query/directory` |
| GET | `/_matrix/federation/v1/query/profile` |
| GET | `/_matrix/federation/v1/query/profile` |
| GET | `/_matrix/federation/v1/state/{roomId}` |
| GET | `/_matrix/federation/v1/state_ids/{roomId}` |
| GET | `/_matrix/federation/v1/version` |
| POST | `/_matrix/federation/v1/get_missing_events/{roomId}` |
| PUT | `/_matrix/federation/v1/send/{txnId}` |
| PUT | `/_matrix/federation/v1/send_join/{roomId}/{eventId}` |
| PUT | `/_matrix/federation/v1/send_leave/{roomId}/{eventId}` |
| PUT | `/_matrix/federation/v2/invite/{roomId}/{eventId}` |

### /_matrix/media/v3/co

| Method | Path |
|--------|------|
| GET | `/_matrix/media/v3/config` |

### /_matrix/media/v3/do

| Method | Path |
|--------|------|
| GET | `/_matrix/media/v3/download/{serverName}/{mediaId}` |

### /_matrix/media/v3/pr

| Method | Path |
|--------|------|
| GET | `/_matrix/media/v3/preview_url` |

### /_matrix/media/v3/th

| Method | Path |
|--------|------|
| GET | `/_matrix/media/v3/thumbnail/{serverName}/{mediaId}` |
| GET | `/_matrix/media/v3/thumbnail/{serverName}/{mediaId}` |

### /_matrix/media/v3/up

| Method | Path |
|--------|------|
| POST | `/_matrix/media/v3/upload` |

### /_synapse/admin/v1/b

| Method | Path |
|--------|------|
| GET | `/_synapse/admin/v1/background_updates/status` |
| GET | `/_synapse/admin/v1/background_updates/{updateName}` |
| POST | `/_synapse/admin/v1/background_updates/start_job` |
| POST | `/_synapse/admin/v1/background_updates/{updateName}/run` |

### /_synapse/admin/v1/d

| Method | Path |
|--------|------|
| POST | `/_synapse/admin/v1/deactivate/{userId}` |

### /_synapse/admin/v1/e

| Method | Path |
|--------|------|
| GET | `/_synapse/admin/v1/event_reports` |
| GET | `/_synapse/admin/v1/event_reports/{reportId}` |

### /_synapse/admin/v1/f

| Method | Path |
|--------|------|
| GET | `/_synapse/admin/v1/federation/destinations` |

### /_synapse/admin/v1/r

| Method | Path |
|--------|------|
| DELETE | `/_synapse/admin/v1/registration_tokens/{token}` |
| DELETE | `/_synapse/admin/v1/rooms/{roomId}` |
| GET | `/_synapse/admin/v1/registration_tokens` |
| GET | `/_synapse/admin/v1/registration_tokens/{token}` |
| GET | `/_synapse/admin/v1/room/{roomId}/media` |
| GET | `/_synapse/admin/v1/rooms/{roomId}/block` |
| GET | `/_synapse/admin/v1/rooms/{roomId}/members` |
| POST | `/_synapse/admin/v1/registration_tokens/new` |
| POST | `/_synapse/admin/v1/reset_password/{userId}` |
| POST | `/_synapse/admin/v1/rooms/{roomId}/make_room_admin` |

### /_synapse/admin/v1/s

| Method | Path |
|--------|------|
| GET | `/_synapse/admin/v1/server_version` |
| GET | `/_synapse/admin/v1/statistics/database/rooms` |

### /_synapse/admin/v1/u

| Method | Path |
|--------|------|
| GET | `/_synapse/admin/v1/users/{userId}/cumulative_joined_room_count` |
| GET | `/_synapse/admin/v1/users/{userId}/external_ids` |
| GET | `/_synapse/admin/v1/users/{userId}/joined_rooms` |
| GET | `/_synapse/admin/v1/users/{userId}/pushers` |
| GET | `/_synapse/admin/v1/users/{userId}/sent_invite_count` |
| POST | `/_synapse/admin/v1/users/{userId}/shadow_ban` |
| PUT | `/_synapse/admin/v1/users/{userId}/admin` |

### /_synapse/admin/v1/w

| Method | Path |
|--------|------|
| GET | `/_synapse/admin/v1/whois/{userId}` |

### /_synapse/admin/v2/r

| Method | Path |
|--------|------|
| DELETE | `/_synapse/admin/v2/rooms/{roomId}` |
| GET | `/_synapse/admin/v2/rooms/{roomId}/delete_status` |

### /_synapse/admin/v2/u

| Method | Path |
|--------|------|
| DELETE | `/_synapse/admin/v2/users/{userId}/devices/{deviceId}` |
| GET | `/_synapse/admin/v2/users` |
| GET | `/_synapse/admin/v2/users` |

### /_synapse/client/new

| Method | Path |
|--------|------|
| GET | `/_synapse/client/new_user_consent` |
| POST | `/_synapse/client/new_user_consent` |

### /_synapse/client/oid

| Method | Path |
|--------|------|
| GET | `/_synapse/client/oidc/callback` |
| POST | `/_synapse/client/oidc/backchannel_logout` |

### /_synapse/client/pas

| Method | Path |
|--------|------|
| GET | `/_synapse/client/password_reset/email/submit_token` |
| GET | `/_synapse/client/password_reset/email/submit_token` |
| POST | `/_synapse/client/password_reset/email/submit_token` |

### /_synapse/client/pic

| Method | Path |
|--------|------|
| GET | `/_synapse/client/pick_idp` |
| GET | `/_synapse/client/pick_username/account_details` |
| GET | `/_synapse/client/pick_username/check` |
| POST | `/_synapse/client/pick_username/account_details` |

### /_synapse/client/ren

| Method | Path |
|--------|------|
| GET | `/_synapse/client/rendezvous/{sessionId}` |

### /_synapse/client/sam

| Method | Path |
|--------|------|
| GET | `/_synapse/client/saml2/authn_response` |
| GET | `/_synapse/client/saml2/metadata.xml` |
| POST | `/_synapse/client/saml2/authn_response` |

### /_synapse/client/sso

| Method | Path |
|--------|------|
| GET | `/_synapse/client/sso_register` |
| GET | `/_synapse/client/sso_register` |
| POST | `/_synapse/client/sso_register` |

### /_synapse/client/uns

| Method | Path |
|--------|------|
| GET | `/_synapse/client/unsubscribe` |

### /_synapse/jwks

| Method | Path |
|--------|------|
| GET | `/_synapse/jwks` |

### /_synapse/mas/allow_

| Method | Path |
|--------|------|
| POST | `/_synapse/mas/allow_cross_signing_reset` |

### /_synapse/mas/reacti

| Method | Path |
|--------|------|
| POST | `/_synapse/mas/reactivate_user` |

### /_synapse/mas/set_di

| Method | Path |
|--------|------|
| POST | `/_synapse/mas/set_displayname` |

### /_synapse/mas/sync_d

| Method | Path |
|--------|------|
| POST | `/_synapse/mas/sync_devices` |

### /_synapse/mas/unset_

| Method | Path |
|--------|------|
| POST | `/_synapse/mas/unset_displayname` |

### /_synapse/mas/update

| Method | Path |
|--------|------|
| POST | `/_synapse/mas/update_device_display_name` |

### r0

| Method | Path |
|--------|------|
| GET | `/_matrix/client/r0/account/3pid` |
| GET | `/_matrix/client/r0/account/whoami` |
| GET | `/_matrix/client/r0/capabilities` |
| GET | `/_matrix/client/r0/devices` |
| GET | `/_matrix/client/r0/directory/room/{alias}` |
| GET | `/_matrix/client/r0/keys/changes` |
| GET | `/_matrix/client/r0/notifications` |
| GET | `/_matrix/client/r0/presence/{userId}/status` |
| GET | `/_matrix/client/r0/pushrules/` |
| GET | `/_matrix/client/r0/sync` |
| POST | `/_matrix/client/r0/account/3pid` |
| POST | `/_matrix/client/r0/account/deactivate` |
| POST | `/_matrix/client/r0/account/password` |
| POST | `/_matrix/client/r0/keys/claim` |
| POST | `/_matrix/client/r0/keys/query` |
| POST | `/_matrix/client/r0/keys/upload` |
| POST | `/_matrix/client/r0/login` |
| POST | `/_matrix/client/r0/logout` |
| POST | `/_matrix/client/r0/logout/all` |
| POST | `/_matrix/client/r0/register` |
| POST | `/_matrix/client/r0/rooms/{roomId}/send/{type}/{txnId}` |
| POST | `/_matrix/client/r0/user/{userId}/filter` |
| PUT | `/_matrix/client/r0/presence/{userId}/status` |
| PUT | `/_matrix/client/r0/sendToDevice/{type}/{txnId}` |

### unstable

| Method | Path |
|--------|------|
| GET | `/_matrix/client/unstable/add_threepid/email/submit_token` |
| GET | `/_matrix/client/unstable/im.nheko.summary/summary/{roomId}` |
| GET | `/_matrix/client/unstable/org.matrix.msc3720/account_status` |
| GET | `/_matrix/client/unstable/org.matrix.msc3983/keys/claim` |
| GET | `/_matrix/client/unstable/org.matrix.msc4140/delayed_events` |
| GET | `/_matrix/client/unstable/registration/{medium}/submit_token` |
| POST | `/_matrix/client/unstable/add_threepid/msisdn/submit_token` |
| POST | `/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}/cancel` |
| POST | `/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}/restart` |
| POST | `/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}/send` |
| POST | `/_matrix/client/unstable/org.matrix.simplified_msc3575/sync` |
| POST | `/_matrix/client/unstable/pushers/remove` |

### v1

| Method | Path |
|--------|------|
| GET | `/_matrix/client/v1/register/m.login.registration_token/validity` |
| GET | `/_matrix/client/v1/rooms/{roomId}/summary` |

### v3

| Method | Path |
|--------|------|
| DELETE | `/_matrix/client/v3/devices/{deviceId}` |
| DELETE | `/_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}` |
| DELETE | `/_matrix/client/v3/directory/room/{roomAlias}` |
| DELETE | `/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}` |
| DELETE | `/_matrix/client/v3/room_keys/keys` |
| DELETE | `/_matrix/client/v3/rooms/{roomId}/thread/{threadId}/subscription` |
| DELETE | `/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}` |
| GET | `/_matrix/client/v3/account/whoami` |
| GET | `/_matrix/client/v3/capabilities` |
| GET | `/_matrix/client/v3/devices` |
| GET | `/_matrix/client/v3/directory/room/{roomAlias}` |
| GET | `/_matrix/client/v3/events` |
| GET | `/_matrix/client/v3/events/{eventId}` |
| GET | `/_matrix/client/v3/initialSync` |
| GET | `/_matrix/client/v3/keys/changes` |
| GET | `/_matrix/client/v3/login` |
| GET | `/_matrix/client/v3/login/cas/redirect` |
| GET | `/_matrix/client/v3/login/cas/ticket` |
| GET | `/_matrix/client/v3/login/sso/redirect` |
| GET | `/_matrix/client/v3/login/sso/redirect/{idp_id}` |
| GET | `/_matrix/client/v3/login/sso/redirect/{idp}` |
| GET | `/_matrix/client/v3/notifications` |
| GET | `/_matrix/client/v3/org.matrix.msc3814.v1/dehydrated_device` |
| GET | `/_matrix/client/v3/org.matrix.msc3866/account_status` |
| GET | `/_matrix/client/v3/password_policy` |
| GET | `/_matrix/client/v3/presence/{userId}/status` |
| GET | `/_matrix/client/v3/profile/{userId}` |
| GET | `/_matrix/client/v3/pushrules/` |
| GET | `/_matrix/client/v3/room_keys/keys` |
| GET | `/_matrix/client/v3/room_keys/version` |
| GET | `/_matrix/client/v3/rooms/{roomId}/aliases` |
| GET | `/_matrix/client/v3/rooms/{roomId}/context/{eventId}` |
| GET | `/_matrix/client/v3/rooms/{roomId}/event/{eventId}` |
| GET | `/_matrix/client/v3/rooms/{roomId}/hierarchy` |
| GET | `/_matrix/client/v3/rooms/{roomId}/initialSync` |
| GET | `/_matrix/client/v3/rooms/{roomId}/joined_members` |
| GET | `/_matrix/client/v3/rooms/{roomId}/members` |
| GET | `/_matrix/client/v3/rooms/{roomId}/preview/{eventId}` |
| GET | `/_matrix/client/v3/rooms/{roomId}/relations/{eventId}` |
| GET | `/_matrix/client/v3/rooms/{roomId}/relations/{eventId}/{relType}` |
| GET | `/_matrix/client/v3/rooms/{roomId}/state` |
| GET | `/_matrix/client/v3/rooms/{roomId}/state/m.room.server_acl` |
| GET | `/_matrix/client/v3/rooms/{roomId}/state/m.room.server_acl` |
| GET | `/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}` |
| GET | `/_matrix/client/v3/rooms/{roomId}/summary` |
| GET | `/_matrix/client/v3/rooms/{roomId}/thread/{threadId}/subscription` |
| GET | `/_matrix/client/v3/rooms/{roomId}/timestamp_to_event` |
| GET | `/_matrix/client/v3/sync` |
| GET | `/_matrix/client/v3/thread_subscriptions/{roomId}` |
| GET | `/_matrix/client/v3/user/{userId}/account_data/{type}` |
| GET | `/_matrix/client/v3/user/{userId}/filter/{filterId}` |
| GET | `/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags` |
| GET | `/_matrix/client/v3/voip/turnServer` |
| POST | `/_matrix/client/v3/account/3pid/email/requestToken` |
| POST | `/_matrix/client/v3/account/3pid/email/requestToken` |
| POST | `/_matrix/client/v3/account/3pid/unbind` |
| POST | `/_matrix/client/v3/account/deactivate` |
| POST | `/_matrix/client/v3/account/password` |
| POST | `/_matrix/client/v3/account/password/email/requestToken` |
| POST | `/_matrix/client/v3/appservice/{appserviceId}/ping` |
| POST | `/_matrix/client/v3/createRoom` |
| POST | `/_matrix/client/v3/keys/claim` |
| POST | `/_matrix/client/v3/keys/device_signing/upload` |
| POST | `/_matrix/client/v3/keys/query` |
| POST | `/_matrix/client/v3/keys/signatures/upload` |
| POST | `/_matrix/client/v3/keys/upload` |
| POST | `/_matrix/client/v3/knock/{roomIdOrAlias}` |
| POST | `/_matrix/client/v3/login` |
| POST | `/_matrix/client/v3/logout` |
| POST | `/_matrix/client/v3/logout/all` |
| POST | `/_matrix/client/v3/org.matrix.msc4108/rendezvous` |
| POST | `/_matrix/client/v3/pushers/set` |
| POST | `/_matrix/client/v3/pushers/set` |
| POST | `/_matrix/client/v3/refresh` |
| POST | `/_matrix/client/v3/register` |
| POST | `/_matrix/client/v3/register/email/requestToken` |
| POST | `/_matrix/client/v3/room_keys/version` |
| POST | `/_matrix/client/v3/rooms/{roomId}/ban` |
| POST | `/_matrix/client/v3/rooms/{roomId}/forget` |
| POST | `/_matrix/client/v3/rooms/{roomId}/invite` |
| POST | `/_matrix/client/v3/rooms/{roomId}/kick` |
| POST | `/_matrix/client/v3/rooms/{roomId}/leave` |
| POST | `/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}` |
| POST | `/_matrix/client/v3/rooms/{roomId}/report` |
| POST | `/_matrix/client/v3/rooms/{roomId}/report/{eventId}` |
| POST | `/_matrix/client/v3/rooms/{roomId}/unban` |
| POST | `/_matrix/client/v3/rooms/{roomId}/upgrade` |
| POST | `/_matrix/client/v3/search` |
| POST | `/_matrix/client/v3/tokenrefresh` |
| POST | `/_matrix/client/v3/user/{userId}/filter` |
| POST | `/_matrix/client/v3/user/{userId}/openid/request_token` |
| POST | `/_matrix/client/v3/user_directory/search` |
| POST | `/_matrix/client/v3/users/{userId}/report` |
| PUT | `/_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}` |
| PUT | `/_matrix/client/v3/directory/room/{roomAlias}` |
| PUT | `/_matrix/client/v3/org.matrix.msc3814.v1/dehydrated_device` |
| PUT | `/_matrix/client/v3/presence/{userId}/status` |
| PUT | `/_matrix/client/v3/profile/{userId}/avatar_url` |
| PUT | `/_matrix/client/v3/profile/{userId}/displayname` |
| PUT | `/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}` |
| PUT | `/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/actions` |
| PUT | `/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/enabled` |
| PUT | `/_matrix/client/v3/room_keys/keys` |
| PUT | `/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}` |
| PUT | `/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` |
| PUT | `/_matrix/client/v3/rooms/{roomId}/state/m.room.server_acl` |
| PUT | `/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}` |
| PUT | `/_matrix/client/v3/rooms/{roomId}/sticky/{eventId}` |
| PUT | `/_matrix/client/v3/rooms/{roomId}/thread/{threadId}/subscription` |
| PUT | `/_matrix/client/v3/user/{userId}/account_data/{type}` |
| PUT | `/_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}` |
| PUT | `/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}` |

### versions

| Method | Path |
|--------|------|
| GET | `/_matrix/client/versions` |


## Federation API (/_matrix/federation/v1/)

| Method | Path |
|--------|------|
| GET | `/version` |
| PUT | `/send/{txnId}` |
| GET | `/event/{eventId}` |
| GET | `/state/{roomId}` |
| GET | `/state_ids/{roomId}` |
| GET | `/backfill/{roomId}` |
| GET | `/event_auth/{roomId}/{eventId}` |
| GET | `/make_join/{roomId}/{userId}` |
| PUT | `/send_join/{roomId}/{eventId}` |
| GET | `/make_leave/{roomId}/{userId}` |
| PUT | `/send_leave/{roomId}/{eventId}` |
| GET | `/make_knock/{roomId}/{userId}` |
| PUT | `/invite/{roomId}/{eventId}` |
| PUT | `/exchange_third_party_invite/{roomId}` |
| POST | `/get_missing_events/{roomId}` |
| POST | `/user/keys/query` |
| POST | `/user/keys/claim` |
| GET | `/user/devices/{userId}` |
| GET | `/hierarchy/{roomId}` |
| GET | `/publicRooms` |
| GET | `/openid/userinfo` |
| GET | `/media/download/{mediaId}` |
| GET | `/media/thumbnail/{mediaId}` |

## IRC Protocol (RFC 1459 + IRCv3)

| Command | Description |
|---------|-------------|
| NICK | Set nickname |
| USER | Set username/realname |
| JOIN | Join channel |
| PART | Leave channel |
| PRIVMSG | Send message to channel/user |
| QUIT | Disconnect |
| PING/PONG | Keepalive |
| MODE | Channel/user modes |
| TOPIC | Get/set channel topic |
| KICK | Remove user from channel |
| INVITE | Invite user to channel |
| WHOIS | Query user info |
| CAP | IRCv3 capability negotiation |
| SASL | Authenticate via SASL PLAIN |
| NICKSERV | Register/identify nick |
| CHANSERV | Register channel |

## XMPP Protocol (RFC 6120 + Extensions)

| XEP | Feature |
|-----|---------|
| XEP-0045 | Multi-User Chat (MUC) |
| XEP-0313 | Message Archive Management |
| XEP-0280 | Message Carbons |
| XEP-0060 | Publish-Subscribe |
| XEP-0054 | vCard-temp |
| XEP-0198 | Stream Management |
| XEP-0030 | Service Discovery |
| RFC 6120 | XML Streams + SASL |
| RFC 6121 | Roster Management |

## Lemmy API (/api/v3/)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/site` | Site info + counts |
| GET | `/community` | Get community by ID |
| GET | `/community/list` | List communities |
| POST | `/community` | Create community |
| POST | `/community/follow` | Subscribe/unsubscribe |
| GET | `/post` | Get post by ID |
| GET | `/post/list` | Front page / community posts |
| POST | `/post` | Create post |
| PUT | `/post` | Edit post |
| DELETE | `/post` | Delete post |
| POST | `/post/like` | Vote on post |
| POST | `/comment` | Create comment |
| PUT | `/comment` | Edit comment |
| DELETE | `/comment` | Delete comment |
| POST | `/comment/like` | Vote on comment |
| GET | `/user` | Get user profile |
| POST | `/user/login` | Login |
| POST | `/user/register` | Register |
| GET | `/user/{username}/outbox` | ActivityPub outbox |
| POST | `/user/{username}/inbox` | ActivityPub inbox |

---

**Total: 255 routes, 4 protocols, 17 600 lines C++23, 89 tests**
