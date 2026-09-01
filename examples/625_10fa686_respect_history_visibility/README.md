# Step 625 — "feat: respect history visibility" (Conduit `10fa686`)

Source: [`timokoesters/conduit@10fa686`](https://github.com/timokoesters/conduit/commit/10fa686) (2023-03)

## What changed vs step 624

| Rust change | C++ translation |
|---|---|
| Feat: respect history visibility. History visibility rules for room events. 8 files changed. MAJOR feature. | **Translated** — We don't have history visibility yet. This adds the feature. |

## Implementation details

- We don't have history visibility yet. This adds the feature.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
