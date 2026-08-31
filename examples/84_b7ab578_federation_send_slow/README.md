# Step 84 — "fix: sending slowness" (Conduit `b7ab578`)

Source: [`timokoesters/conduit@b7ab578`](https://github.com/timokoesters/conduit/commit/b7ab578) (2020-09)

## What changed vs step 83

| Rust change | C++ translation |
|---|---|
| Fix: federation sending is slow because it blocks the user request. Hands off the send to a detached background thread. | Our step 38 (`b7ab57897_sendslow`) implements `federation_send_background` with `std::thread::detach()`. |

## Implementation details

- Our step 38 (`b7ab57897_sendslow`) implements `federation_send_background` with `std::thread::detach()`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
