# Step 149 — "feat: /event_auth" (Conduit `67f9592b`)

Source: [`timokoesters/conduit@67f9592b`](https://github.com/timokoesters/conduit/commit/67f9592b) (2021-06-18)

Upstream adds the federation `GET /event_auth/:roomId/:eventId` endpoint,
returning the auth chain for an event.

## What changed vs step 148

**Nothing in `src/` — this directory was a byte-identical copy.** The change
is implemented in the modern chain as step 805
(`805_67f9592b_event_auth`), which serves the auth chain by walking
`auth_events` (missing links skipped).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit149 && ./build/tests
```
