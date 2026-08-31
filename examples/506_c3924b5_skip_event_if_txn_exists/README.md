# Step 506 — "feat: if txn id exists in the db, skip the event" (Conduit `c3924b5`)

Source: [`timokoesters/conduit@c3924b5`](https://github.com/timokoesters/conduit/commit/c3924b5) (2022-06)

## What changed vs step 505

| Rust change | C++ translation |
|---|---|
| Feat: if txn id exists in the db, skip the event. Deduplication via transaction ID. 1 file changed. | **Translated** — Our /send (step 29) handles txn IDs. This adds deduplication check. |

## Implementation details

- Our /send (step 29) handles txn IDs. This adds deduplication check.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
