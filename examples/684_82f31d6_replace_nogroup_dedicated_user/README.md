# Step 684 — "Replace nogroup with dedicated user group" (Conduit `82f31d6`)

Source: [`timokoesters/conduit@82f31d6`](https://github.com/timokoesters/conduit/commit/82f31d6) (2023-07)

## What changed vs step 683

| Rust change | C++ translation |
|---|---|
| Replace nogroup with dedicated user group. System user/group configuration. | **No-op for us** — System deployment — our C++ runs as current user. |

## Implementation details

- System deployment — our C++ runs as current user.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
