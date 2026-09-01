# Step 690 — "Sliding sync subscriptions, e2ee, to_device messages" (Conduit `d220641`)

Source: [`timokoesters/conduit@d220641`](https://github.com/timokoesters/conduit/commit/d220641) (2023-07)

## What changed vs step 689

| Rust change | C++ translation |
|---|---|
| Sliding sync subscriptions, e2ee, to_device messages. Sliding sync with E2EE and to-device support. 2 files changed. | **Translated** — Follows step 670/689. Adds subscriptions, E2EE, and to-device to sliding sync. |

## Implementation details

- Follows step 670/689. Adds subscriptions, E2EE, and to-device to sliding sync.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
