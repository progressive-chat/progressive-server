# Step 413 — "fix: make sure that libatomic is linked statically" (Conduit `acf1585`)

Source: [`timokoesters/conduit@acf1585`](https://github.com/timokoesters/conduit/commit/acf1585) (2022-01)

## What changed vs step 412

| Rust change | C++ translation |
|---|---|
| Fix: make sure that libatomic is linked statically. Static linking fix. | **No-op for us** — Rust linking — N/A for C++. |

## Implementation details

- Rust linking — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
