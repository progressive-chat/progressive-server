# Step 129 — "feat: send logs into admin room" (Conduit `9439f2c`)

Source: [`timokoesters/conduit@9439f2c`](https://github.com/timokoesters/conduit/commit/9439f2c) (2020-12)

## What changed vs step 128

| Rust change | C++ translation |
|---|---|
| Sends log messages into the admin room. The admin can read these messages to monitor the server. | **Translated** — Our admin subsystem (step 60) supports this — log messages are forwarded to the admin room. |

## Implementation details

- Our admin subsystem (step 60) supports this — log messages are forwarded to the admin room.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
