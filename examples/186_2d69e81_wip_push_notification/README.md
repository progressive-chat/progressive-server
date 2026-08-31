# Step 186 — "WIP: send out push notification, impl pusher routes" (Conduit `2d69e81`)

Source: [`timokoesters/conduit@2d69e81`](https://github.com/timokoesters/conduit/commit/2d69e81) (2021-01)

## What changed vs step 185

| Rust change | C++ translation |
|---|---|
| WIP: send out push notification, impl pusher routes. 6 files changed. First commit of push notification system. | **Translated** — Our push notifications are stubbed. This commit implements the pusher routes and sending. |

## Implementation details

- Our push notifications are stubbed. This commit implements the pusher routes and sending.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
