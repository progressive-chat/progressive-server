# Step 127 — "feat: send read receipts over federation" (Conduit `8f27e61`)

Source: [`timokoesters/conduit@8f27e61`](https://github.com/timokoesters/conduit/commit/8f27e61) (2021-05-17)

Upstream forwards local users' read receipts to remote servers: when a
federation transaction has to be sent anyway, the pending `m.receipt` EDUs for
that server are appended to it. This directory used to be a byte-identical
copy of the attempt-A base; it is rebuilt on the previous real step (126) and
now really implements the commit.

## What changed vs step 126

| Rust change | C++ translation |
|---|---|
| **`serverroomids` tree (ServerName+0xff+RoomId) + `Rooms::server_rooms()`** | **Implemented** — new tree, `Data::server_rooms()`, populated from `update_membership()` on join/invite/leave (the port previously never populated `roomserverids` either — that is fixed too, so `room_servers()` finally works) |
| **Database migration 0 → 1 (build serverroomids from roomserverids)** | **Implemented** — runs once in the `Data` constructor, versioned via the database root `version` key |
| **`servername_educount` tree (last EDU count sent per server)** | **Implemented** — new tree |
| **`Sending::select_edus()`** | **Implemented** — `Data::select_edus(server)`: walks the server's rooms, takes up to 20 receipts newer than the stored count, skips remote users, builds the federation `m.receipt` EDU, advances the count |
| **Append EDUs to outgoing transactions (`select_events`)** | **Implemented** — the invite fan-out and federation join send now attach `"edus"` to the transaction body |
| **`readreceipts_since` returns `(UserId, count, event)`** | **Implemented** — `Data::Receipt` + `readreceipts_since()` |
| **`sync.rs` tuple mapping** | **Implemented** — sync takes the event value |
| **Receipt storage + `POST /rooms/{roomId}/receipt/{type}/{eventId}` + sync ephemeral events (prerequisites, `dd68031` era)** | **Folded** — `readreceiptid_readreceipt` tree, `Data::readreceipt_update()`, the client route (resets notification counts like upstream), and `ephemeral.events` in joined rooms |
| **Incoming EDU handling in `/send`** | **Folded** — incoming `m.receipt` EDUs are stored so remote receipts show up in sync |

Documented port limitations (the port's event stream predates Conduit's single
global counter):
- Sync `since` is a per-room PDU index while receipts use a global receipt
  counter (upstream shares one global counter for both). Initial syncs return
  all receipts; incremental receipt filtering is therefore approximate.
- The port only sends federation PDUs on the invite fan-out and join paths
  (it does not federate regular messages), so — exactly like upstream's note
  "currently they will only be sent if a PDU has to be sent as well" — receipts
  ride along when one of those transactions goes out.

Steps covered elsewhere: 123 (cf94b8e → modern 118), 124 (docs/config only),
125 (canonical-JSON refactor), 126 (presence, previous step).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit127
# alice reads a message; /sync then carries it as an ephemeral event:
$ curl -s -X POST -H "Authorization: Bearer $ALICE" \
    http://127.0.0.1:8000/_matrix/client/r0/rooms/$ROOM/receipt/m.read/$EVENT
$ curl -s -H "Authorization: Bearer $ALICE" "http://127.0.0.1:8000/_matrix/client/r0/sync?since=0" \
  | jq '.rooms.join[].ephemeral.events'
```
