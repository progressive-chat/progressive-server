# Step 63 — "improvement: send 200 response for turn server info" (Conduit `ad7b3f1`)

Source: [`timokoesters/conduit@ad7b3f1`](https://github.com/timokoesters/conduit/commit/ad7b3f1) (2021-01-11)

## What changed vs step 62

| Rust change | C++ translation |
|---|---|
| **Send 200 response for turn server info** | **Translated** — Return 200 with empty TURN servers |
| **Stop clients from retrying endpoint** | **Translated** — Proper response code |

## Implementation details

1. **TURN server info endpoint** — Returns 200 OK with empty TURN server list
2. **Client retry prevention** — Proper response stops clients from retrying every minute

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
