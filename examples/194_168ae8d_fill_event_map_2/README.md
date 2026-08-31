# Step 194 — "Fill event_map with all events that will be needed for resolution" (Conduit `168ae8d`)

Source: [`timokoesters/conduit@168ae8d`](https://github.com/timokoesters/conduit/commit/168ae8d) (2021-02)

## What changed vs step 193

| Rust change | C++ translation |
|---|---|
| Fill event_map with all events that will be needed for resolution. Continuation of state-res work. | **Translated** — Our state-res caches all needed events for resolution. |

## Implementation details

- Our state-res caches all needed events for resolution.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
