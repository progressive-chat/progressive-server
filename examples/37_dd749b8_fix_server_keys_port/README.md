# Step 37 — "fix: server keys and destination resolution when server name contains port" (Conduit `dd749b8`)

Source: [`timokoesters/conduit@dd749b8`](https://github.com/timokoesters/conduit/commit/dd749b8) (2020-09-15)

## What changed vs step 36

| Rust change | C++ translation |
|---|---|
| **Keypair format**: Added version prefix (version + 0xff + key) | **Translated** — Updated keypair generation and loading to include version prefix |
| **Keypair loading**: Added error handling with error logging and auto-deletion | **Translated** — Added error handling with logging and auto-deletion of invalid keypairs |
| **Destination resolution**: Fixed to handle server names with/without ports | **Translated** — Added port handling in destination resolution |
| **Keypair generation**: Added version prefix (version + 0xff + key) | **Translated** — Updated keypair generation |

## Implementation details

1. **globals/keypair**: 
   - Added version prefix (1 byte version + 0xff + key) to keypair storage
   - Added error handling with logging and auto-deletion of invalid keypairs
   - Updated keypair loading to parse versioned format

2. **Destination resolution**:
   - If server name contains ':', use as-is (includes port)
   - Otherwise append ":8448" as default port

3. **Keypair generation**:
   - Added version prefix (1 byte version + 0xff + key)
   - Version 1 for new keypairs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
