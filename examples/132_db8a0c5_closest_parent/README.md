# Step 132 — "Add closest_parent method to Rooms Db insert in order /send pdus" (Conduit `db8a0c5`)

Source: [`timokoesters/conduit@db8a0c5`](https://github.com/timokoesters/conduit/commit/db8a0c5) (2020-12)

## What changed vs step 131

| Rust change | C++ translation |
|---|---|
| Adds the `closest_parent` method to Rooms DB. Used in `/send` PDU insertion to find the correct ordering of events. | **Translated** — Our `pdu_append` (step 6) uses `prev_events` to determine ordering. The `closest_parent` helper is folded into the state-res work. |

## Implementation details

- Our `pdu_append` (step 6) uses `prev_events` to determine ordering. The `closest_parent` helper is folded into the state-res work.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
