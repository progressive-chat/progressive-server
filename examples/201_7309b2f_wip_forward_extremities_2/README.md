# Step 201 — "WIP gather and update forward extremities" (Conduit `7309b2f`)

Source: [`timokoesters/conduit@7309b2f`](https://github.com/timokoesters/conduit/commit/7309b2f) (2021-02)

## What changed vs step 200

| Rust change | C++ translation |
|---|---|
| WIP gather and update forward extremities. Duplicate of step 178 (c65bde4). | **Translated** — Our state-res computes forward extremities via `pdu_leaves_replace`. |

## Implementation details

- Our state-res computes forward extremities via `pdu_leaves_replace`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
