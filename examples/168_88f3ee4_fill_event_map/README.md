# Step 168 — "Fill event_map with all events that will be needed for resolution" (Conduit `88f3ee4`)

Source: [`timokoesters/conduit@88f3ee4`](https://github.com/timokoesters/conduit/commit/88f3ee4) (2021-01)

## What changed vs step 167

| Rust change | C++ translation |
|---|---|
| Fill `event_map` with all events that will be needed for resolution. Adds more events to the local cache for the next state resolution. | **Translated** — Our state-res caches events in memory for the duration of the resolution. |

## Implementation details

- Our state-res caches events in memory for the duration of the resolution.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
