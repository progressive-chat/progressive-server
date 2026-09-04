# Step 92 — "fix: multiple federation/pusher fixes" (Conduit `44425a9`)

Source: [`timokoesters/conduit@44425a9`](https://github.com/timokoesters/conduit/commit/44425a9) (2021-03-16)

## What changed vs step 91

| Rust change | C++ translation |
|---|---|
| **Multiple federation/pusher fixes** | **No-op for us** — Cleaned up debug prints |
| **Major error.rs cleanup** | **No-op for us** — No custom logger |
| **Major server_server refactor** | **No-op for us** — No custom logger |

## Implementation details

This Conduit commit removes debug macros (`dbg!()`, `dbg!()`, `println!()`) and removes a custom `ConduitLogger` implementation that sent admin messages via log crate.

**In our C++ implementation:**
- We don't use Rust's `dbg!()`/`println!()` debug macros
- We don't have a custom `ConduitLogger` equivalent (we use `std::cerr` directly)
- Log level changes (info→debug) in server_server.rs are not applicable since we use `std::cerr` for all logging

**Status:** No-op for us (already clean)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```