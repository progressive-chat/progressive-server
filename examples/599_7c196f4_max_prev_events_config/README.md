# Step 599 — "feat: Add max prev events config option, allowing adjusting limit for prev_events fetching" (Conduit `7c196f4`)

Source: [`timokoesters/conduit@7c196f4`](https://github.com/timokoesters/conduit/commit/7c196f4) (2022-12)

## What changed vs step 598

| Rust change | C++ translation |
|---|---|
| Feat: Add max prev events config option, allowing adjusting limit for prev_events fetching. Configurable prev_events limit. 3 files changed. | **Translated** — Our federation (step 29) fetches prev_events. This adds a config option for the limit. |

## Implementation details

- Our federation (step 29) fetches prev_events. This adds a config option for the limit.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
