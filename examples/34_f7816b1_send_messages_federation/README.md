# Step 34 — "feat: send messages over federation" (Conduit `f7816b1`)

Source: [`timokoesters/conduit@f7816b1`](https://github.com/timokoesters/conduit/commit/f7816b1) (2020-09-15)

## What changed vs step 33

| Rust change | C++ translation |
|---|---|
| **`send_request`** takes `&Globals` instead of `&Database` | **Translated** — Updated `send_request` signature to use `Globals` |
| **`build_and_append_pdu`** becomes async and sends federation transactions | **Translated** — Made `build_and_append_pdu` async and added federation transaction sending |
| **Added `roomserverids` tree** to track participating servers | **Translated** — Added `roomserverids` tree to track participating servers |
| **`PduEvent::to_outgoing_federation_event`** method added | **Translated** — Added `to_outgoing_federation_event` method |
| **`append_pdu`** takes pdu_json parameter | **Translated** — Updated `append_pdu` to accept pdu_json |
| **`build_and_append_pdu`** becomes async and sends federation transactions | **Translated** — Made async and added federation transaction sending |
| **`PduEvent::to_outgoing_federation_event`** method added | **Translated** — Added method to convert PDU to federation format |

## Implementation details

This is a MAJOR commit (15 files, 324 insertions, 218 deletions) that implements the core federation message sending:

1. **`send_request`** now takes `&Globals` instead of `&Database`
2. **`build_and_append_pdu`** is now async and sends federation transactions after appending PDU
3. **`roomserverids` tree** added to track participating servers in a room
3. **`PduEvent::to_outgoing_federation_event`** converts PDU to federation format
3. **`append_pdu`** takes pdu_json parameter
4. **`build_and_append_pdu`** is now async and sends federation transaction after appending PDU

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
