# Step 212 — "Fix leaves not being replaced by correct eventId in membership" (Conduit `0dd8a15`)

Source: [`timokoesters/conduit@0dd8a15`](https://github.com/timokoesters/conduit/commit/0dd8a15) (2021-02)

## What changed vs step 211

| Rust change | C++ translation |
|---|---|
| Fix leaves not being replaced by correct eventId in membership. Membership events should update the room leaves correctly. | **Translated** — Our `pdu_leaves_replace` handles membership events correctly. |

## Implementation details

- Our `pdu_leaves_replace` handles membership events correctly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
