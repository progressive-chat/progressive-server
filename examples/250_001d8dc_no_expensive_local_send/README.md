# Step 250 — "fix: don't do expensive operation on local /send" (Conduit `001d8dc`)

Source: [`timokoesters/conduit@001d8dc`](https://github.com/timokoesters/conduit/commit/001d8dc) (2021-04)

## What changed vs step 249

| Rust change | C++ translation |
|---|---|
| Fix: don't do expensive operation on local /send. Optimize local event sending by skipping unnecessary work. 2 files changed. | **Translated** — Our `/send` (step 29) has local optimization. This avoids state-res for local events. |

## Implementation details

- Our `/send` (step 29) has local optimization. This avoids state-res for local events.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
