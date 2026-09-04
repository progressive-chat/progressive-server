# Step 63 — "improvement: send 200 response for turn server info" (Conduit `ad7b3f1`)

Source: [`timokoesters/conduit@ad7b3f1`](https://github.com/timokoesters/conduit/commit/ad7b3f1) (2021-01-11)

## What changed vs step 62

| Rust change | C++ translation |
|---|---|
| **Send 200 response for turn server info** | **Translated** — Added GET /_matrix/client/r0/voip/turnServer endpoint |
| **Stop clients from retrying endpoint** | **Translated** — Returns 200 with empty TURN servers |

## Implementation details

1. **Added GET /_matrix/client/r0/voip/turnServer endpoint** in main.cpp:
   - Returns 200 OK with empty TURN servers list: `{"uris": []}`
   - This prevents clients from retrying the endpoint every minute

**Status:** Real implementation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```