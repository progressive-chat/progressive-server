# Step 390 — "name the function after its purpose: iter_locals -> get_local_users" (Conduit `c03bf6e`)

Source: [`timokoesters/conduit@c03bf6e`](https://github.com/timokoesters/conduit/commit/c03bf6e) (2022-01)

## What changed vs step 389

| Rust change | C++ translation |
|---|---|
| Name the function after its purpose: iter_locals -> get_local_users. Function rename for clarity. | **No-op for us** — Rust function rename — our C++ uses get_local_users. |

## Implementation details

- Rust function rename — our C++ uses get_local_users.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
