# Step 662 — "Do soft fail check before doing state res to allow leave events" (Conduit `d64a56d`)

Source: [`timokoesters/conduit@d64a56d`](https://github.com/timokoesters/conduit/commit/d64a56d) (2023-06)

## What changed vs step 661

| Rust change | C++ translation |
|---|---|
| Do soft fail check before doing state res to allow leave events. Soft fail check ordering. 1 file changed. | **Translated** — Our state resolution checks soft fails. This fixes the ordering in Rust. |

## Implementation details

- Our state resolution checks soft fails. This fixes the ordering in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
