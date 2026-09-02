# Step 83 — "Fill event_map with all events that will be needed for resolution" (Conduit `168ae8d`)

Source: [`timokoesters/conduit@168ae8d`](https://github.com/timokoesters/conduit/commit/168ae8d) (2021-02-09)

## What changed vs step 82

| Rust change | C++ translation |
|---|---|
| **Fill event_map with all events needed** | **Translated** — Event map for resolution |

## Implementation details

1. **Event map filling** — Fill event_map with all events that will be needed for resolution
2. **State resolution** — Better state resolution support

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
