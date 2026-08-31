# Step 277 — "add dbg_macro check" (Conduit `268ad34`)

Source: [`timokoesters/conduit@268ad34`](https://github.com/timokoesters/conduit/commit/268ad34) (2021-05)

## What changed vs step 276

| Rust change | C++ translation |
|---|---|
| Add dbg_macro check. Debug macro for development. | **No-op for us** — Rust debug macro — N/A for C++. |

## Implementation details

- Rust debug macro — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
