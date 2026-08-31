# Step 178 — "WIP gather and update forward extremities" (Conduit `c65bde4`)

Source: [`timokoesters/conduit@c65bde4`](https://github.com/timokoesters/conduit/commit/c65bde4) (2021-01)

## What changed vs step 177

| Rust change | C++ translation |
|---|---|
| WIP: gather and update forward extremities. Forward extremities are the latest events in a room (no children). | **Translated** — Our state-res (step 83) computes forward extremities via `pdu_leaves_replace`. |

## Implementation details

- Our state-res (step 83) computes forward extremities via `pdu_leaves_replace`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
