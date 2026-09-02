# Step 155 — "Fix docs for fetch_and_handle_events" (Conduit `1bb84a8`)

Source: [`timokoesters/conduit@1bb84a8`](https://github.com/timokoesters/conduit/commit/1bb84a8) (2021-06-30)

## What changed vs step 154

| Rust change | C++ translation |
|---|---|
| **Fix docs for fetch_and_handle_events** | **Translated** — Doc fixes |

## Implementation details

1. **Doc fixes** — Fix docs for fetch_and_handle_events

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
