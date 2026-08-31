# Step 225 — "fix: multiple federation/pusher fixes" (Conduit `44425a9`)

Source: [`timokoesters/conduit@44425a9`](https://github.com/timokoesters/conduit/commit/44425a9) (2021-03)

## What changed vs step 224

| Rust change | C++ translation |
|---|---|
| Fix: multiple federation/pusher fixes. Various bug fixes in federation sending and push notifications. 7 files changed. | **Translated** — Our federation (step 29) and push (steps 186-187) cover this. These are bug fixes. |

## Implementation details

- Our federation (step 29) and push (steps 186-187) cover this. These are bug fixes.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
