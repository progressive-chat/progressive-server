# Step 685 — "Fix up permissions of the database path" (Conduit `8cf408e`)

Source: [`timokoesters/conduit@8cf408e`](https://github.com/timokoesters/conduit/commit/8cf408e) (2023-07)

## What changed vs step 684

| Rust change | C++ translation |
|---|---|
| Fix up permissions of the database path. Database file permissions. | **No-op for us** — System deployment — N/A for C++. |

## Implementation details

- System deployment — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
