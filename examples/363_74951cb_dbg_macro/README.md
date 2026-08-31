# Step 363 — "dbg" (Conduit `74951cb`)

Source: [`timokoesters/conduit@74951cb`](https://github.com/timokoesters/conduit/commit/74951cb) (2022-01)

## What changed vs step 362

| Rust change | C++ translation |
|---|---|
| dbg. Debug macro usage. | **No-op for us** — Rust debug macro — N/A for C++. |

## Implementation details

- Rust debug macro — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
