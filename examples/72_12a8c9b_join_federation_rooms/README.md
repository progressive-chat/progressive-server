# Step 72 — "fix: join rooms over federation" (Conduit `12a8c9b`)

Source: [`timokoesters/conduit@12a8c9b`](https://github.com/timokoesters/conduit/commit/12a8c9b) (2020-09)

## What changed vs step 71

| Rust change | C++ translation |
|---|---|
| The BIG one — implements federation joins. Adds server-side federation endpoints: `/_matrix/federation/v1/send_join/{r}/{u}`, `/state_ids/{r}/{u}`, `/event/{eid}`, `/backfill/{r}`, `/query/directory`. | **Translated** — our step 29 (`12a8c9ba_federation_join`) implements all these endpoints. |

## Implementation details

- **Translated** — our step 29 (`12a8c9ba_federation_join`) implements all these endpoints.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
