# Step 87 — "fix: server keys and destination resolution when server name contains port" (Conduit `dd749b8`)

Source: [`timokoesters/conduit@dd749b8`](https://github.com/timokoesters/conduit/commit/dd749b8) (2020-09)

## What changed vs step 86

| Rust change | C++ translation |
|---|---|
| Fix: server names with ports (e.g., `localhost:8448`) were not resolved correctly. Now parses `:port` from the destination. | Our step 41 (`dd749b8ae_srvport`) implements the port parsing in `send_request`. |

## Implementation details

- Our step 41 (`dd749b8ae_srvport`) implements the port parsing in `send_request`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
