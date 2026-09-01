# Step 724 — "Do not show "Invalid room version" errors when server is not in room" (Conduit `11103a9`)

Source: [`timokoesters/conduit@11103a9`](https://github.com/timokoesters/conduit/commit/11103a9) (2023-08)

## What changed vs step 723

| Rust change | C++ translation |
|---|---|
| Do not show 'Invalid room version' errors when server is not in room. Suppress room version errors for non-members. 4 files changed. | **Translated** — Our room version handling (steps 80-87) works. This suppresses errors for non-members. |

## Implementation details

- Our room version handling (steps 80-87) works. This suppresses errors for non-members.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
