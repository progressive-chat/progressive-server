# Step 39 — "improvement: look at SRV record when sending requests" (Conduit `e08dfd9`)

Source: [`timokoesters/conduit@e08dfd9`](https://github.com/timokoesters/conduit/commit/e08dfd9) (2020-09-23)

## What changed vs step 38

| Rust change | C++ translation |
|---|---|
| **Added `trust-dns-resolver` dependency** for SRV record lookups | **Translated** — Added SRV record lookup capability |
| **`request_well_known`** now returns delegated hostname | **Translated** — Updated to return delegated hostname for SRV lookup |
| **`send_request`** now uses SRV record lookup for federation | **Translated** — Added SRV record lookup in `send_request` |
| **Added HOST header** for virtual hosting support | **Translated** — Added HOST header when using SRV delegation |
| **Added 30-second timeout** for federation requests | **Translated** — Added 30-second timeout to federation requests |

## Implementation details

1. **SRV record lookup**: When sending federation requests, first check `.well-known/matrix/server` for delegation, then look up `_matrix._tcp.<delegated_host>` SRV record to find the actual target server and port.

2. **HOST header**: When using SRV delegation, set the HOST header to the delegated hostname for virtual hosting support.

3. **Timeout**: Added 30-second timeout for federation requests.

3. **Well-known delegation**: The `.well-known/matrix/server` response is used to find the delegated hostname for SRV lookup.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
