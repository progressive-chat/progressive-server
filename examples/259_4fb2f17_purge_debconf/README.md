# Step 259 — "Purge debconf changes from the DB on purge" (Conduit `4fb2f17`)

Source: [`timokoesters/conduit@4fb2f17`](https://github.com/timokoesters/conduit/commit/4fb2f17) (2021-04)

## What changed vs step 258

| Rust change | C++ translation |
|---|---|
| Purge debconf changes from the DB on purge. Debian package cleanup. | **Skipped** — Debian packaging only. |

## Implementation details

- Debian packaging only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
