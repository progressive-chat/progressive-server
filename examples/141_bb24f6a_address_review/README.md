# Step 141 — "Address some review issues fmt, errors, comments" (Conduit `bb24f6a`)

Source: [`timokoesters/conduit@bb24f6a`](https://github.com/timokoesters/conduit/commit/bb24f6a) (2020-12)

## What changed vs step 140

| Rust change | C++ translation |
|---|---|
| Address some review issues: fmt, errors, comments. | **No-op for us** — Rust review feedback — N/A for C++. |

## Implementation details

- Rust review feedback — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
