# Step 68 — "Use the auth_events for step 6, WIP forward_extremity_ids fn" (Conduit `96dc6be`)

Source: [`timokoesters/conduit@96dc6be`](https://github.com/timokoesters/conduit/commit/96dc6be) (2021-01-15)

## What changed vs step 67

| Rust change | C++ translation |
|---|---|
| **Use auth_events for step 6** | **Translated** — auth_events in state res |
| **WIP forward_extremity_ids fn** | **Translated** — Work in progress |

## Implementation details

1. **Auth events in step 6** — Use auth_events for state resolution step 6
2. **Forward extremity IDs** — WIP function for forward extremity IDs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
