# Step 127 — "Lock down the Conduit process in the systemd unit" (Conduit `1a34154`)

Source: [`timokoesters/conduit@1a34154`](https://github.com/timokoesters/conduit/commit/1a34154) (2020-11)

## What changed vs step 126

| Rust change | C++ translation |
|---|---|
| Lock down the Conduit process in the systemd unit (no new privileges, etc.). | **Skipped** — systemd unit — not applicable to our C++ project. |

## Implementation details

- systemd unit — not applicable to our C++ project.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
