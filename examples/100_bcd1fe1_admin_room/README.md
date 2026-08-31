# Step 100 — "feat: admin room" (Conduit `bcd1fe1`)

Source: [`timokoesters/conduit@bcd1fe1`](https://github.com/timokoesters/conduit/commit/bcd1fe1) (2020-10)

## What changed vs step 99

| Rust change | C++ translation |
|---|---|
| Adds the `admin room` feature. A special room where the server sends log messages and the server admin can issue commands. | **Translated** — Our step 60 (`9db1f5a13c_admin`) implements the admin subsystem including the admin room. |

## Implementation details

- Our step 60 (`9db1f5a13c_admin`) implements the admin subsystem including the admin room.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
