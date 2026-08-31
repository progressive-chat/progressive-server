# Step 509 — "Hide users from user directory if they are only in private rooms and they don't share a room" (Conduit `7239243`)

Source: [`timokoesters/conduit@7239243`](https://github.com/timokoesters/conduit/commit/7239243) (2022-06)

## What changed vs step 508

| Rust change | C++ translation |
|---|---|
| Hide users from user directory if they are only in private rooms and they don't share a room. Privacy improvement for user directory. 2 files changed. | **Translated** — Our user directory (step 253) shows users. This adds privacy filtering. |

## Implementation details

- Our user directory (step 253) shows users. This adds privacy filtering.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
