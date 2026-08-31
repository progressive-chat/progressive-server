# Step 211 — "Use auth_cache to avoid db, save state for every event when joining" (Conduit `4860114`)

Source: [`timokoesters/conduit@4860114`](https://github.com/timokoesters/conduit/commit/4860114) (2021-02)

## What changed vs step 210

| Rust change | C++ translation |
|---|---|
| Use auth_cache to avoid DB, save state for every event when joining. Caches auth events to avoid DB lookups during state resolution. | **Translated** — Our state-res caches auth events in memory during resolution. |

## Implementation details

- Our state-res caches auth events in memory during resolution.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
