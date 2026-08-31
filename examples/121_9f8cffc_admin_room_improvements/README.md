# Step 121 — "Admin room improvements" (Conduit `9f8cffc`)

Source: [`timokoesters/conduit@9f8cffc`](https://github.com/timokoesters/conduit/commit/9f8cffc) (2020-11)

## What changed vs step 120

| Rust change | C++ translation |
|---|---|
| Big improvements to the admin room: command parsing, help text, error handling. 18 files changed. | **Translated** — Our step 60 (`9db1f5a13c_admin`) implements the basic admin subsystem. The richer command parsing is part of the admin subsystem's evolution. |

## Implementation details

- Our step 60 (`9db1f5a13c_admin`) implements the basic admin subsystem. The richer command parsing is part of the admin subsystem's evolution.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
