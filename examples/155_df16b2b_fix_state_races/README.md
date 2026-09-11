# Step 155 — "fix: rare state races" (Conduit `df16b2b`)

Source: [`timokoesters/conduit@df16b2b`](https://github.com/timokoesters/conduit/commit/df16b2b) (2020-12-31)

Upstream stores the room state only after the PDU itself is inserted (so
state never references missing events) and drops leftover debug macros.

## What changed vs step 154

**Nothing in `src/` — this directory was a byte-identical copy.** The port
already sets the room state after inserting the PDU (`set_room_state`
follows the store, with the same never-dangling rationale documented), so
the ordering fix is covered; the `dbg!` removals are log cleanup.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit155 && ./build/tests
```
