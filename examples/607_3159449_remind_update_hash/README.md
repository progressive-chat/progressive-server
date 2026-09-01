# Step 607 — "remind people to update the hash" (Conduit `3159449`)

Source: [`timokoesters/conduit@3159449`](https://github.com/timokoesters/conduit/commit/3159449) (2022-12)

## What changed vs step 606

| Rust change | C++ translation |
|---|---|
| Remind people to update the hash. CI reminder. | **No-op for us** — CI reminder — N/A for C++. |

## Implementation details

- CI reminder — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
