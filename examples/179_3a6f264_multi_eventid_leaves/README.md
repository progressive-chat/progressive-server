# Step 179 — "Add ability to update room leaves with multiple eventIds" (Conduit `3a6f264`)

Source: [`timokoesters/conduit@3a6f264`](https://github.com/timokoesters/conduit/commit/3a6f264) (2021-01)

## What changed vs step 178

| Rust change | C++ translation |
|---|---|
| Add ability to update room leaves with multiple event IDs. The `pdu_leaves_replace` can now take multiple event IDs. | **Translated** — Our `pdu_leaves_replace` (step 66 `a254c9b_incoming_event_fix`) already accepts multiple leaves. |

## Implementation details

- Our `pdu_leaves_replace` (step 66 `a254c9b_incoming_event_fix`) already accepts multiple leaves.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
