# Step 11 — "feat: federated room directory" (Conduit `720cc0cf`, 2020-04-25)

Source: [`timokoesters/conduit@720cc0cf`](https://github.com/timokoesters/conduit/commit/720cc0cf)
(+ the folded `873d1915` "http body as content when signing") — federation
requests become spec-shaped and the public directory goes federated.

## What changed vs step 10

| Rust change | C++ translation |
|---|---|
| request bodies travel under a **`"content"` key** inside the signed JSON (873d1915's fix) | `request_map["content"] = content` when non-empty (`server_server.cpp`) |
| federation targets **port 8448** | `httplib::SSLClient(destination, 8448)` |
| signed map's `destination` hardcoded to `"privacytools.io"` while connecting elsewhere — a debugging leftover upstream, preserved verbatim with a loud comment | same hardcoding |
| key document `valid_until_ts` cut from 24h to **2 minutes** | identical |
| publicRooms: local rooms sorted FIRST, then extended with `chat.privacytools.io` results (upstream moved koesters.xyz→privacytools.io) | same destination + ordering |
| `generate_keypair` keeps an existing pair when present | our loader already did |

## Verified

All six test scenarios pass, including both signature checks. Key documents
now expire after 2 minutes:

```console
$ curl .../​_matrix/key/v2/server | python3 -c '…'
valid_until_ts: 1787677799955 (now+120s)
```

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```

## Study note

The hardcoded `"privacytools.io"` destination inside an otherwise-parameterized
function is exactly the kind of debugging leftover that ships in real repos —
the signature covers a different server than the one contacted, which real
remotes would reject. Preserved deliberately: reading history means seeing the
warts too.
