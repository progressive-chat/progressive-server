# Step 202 — "fix: pushers" (Conduit `835cf80`)

Source: [`timokoesters/conduit@835cf80`](https://github.com/timokoesters/conduit/commit/835cf80) (2021-02)

## What changed vs step 201

| Rust change | C++ translation |
|---|---|
| Fix: pushers. Bug fixes in the push notification delivery system. | **Translated** — Our push notifications (steps 186-187) implement the pusher system. This fixes bugs in it. |

## Implementation details

- Our push notifications (steps 186-187) implement the pusher system. This fixes bugs in it.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
