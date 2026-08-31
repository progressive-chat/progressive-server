# Step 82 — "fix: send to all servers and fix media store" (Conduit `71500b1`)

Source: [`timokoesters/conduit@71500b1`](https://github.com/timokoesters/conduit/commit/71500b1) (2020-09)

## What changed vs step 81

| Rust change | C++ translation |
|---|---|
| Fix: federation send now iterates all participating servers (not just one). Also fixes a media store bug. | Our step 36 (`71500b14b_fed_sendall`) implements the send-to-all-servers logic. |

## Implementation details

- Our step 36 (`71500b14b_fed_sendall`) implements the send-to-all-servers logic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
