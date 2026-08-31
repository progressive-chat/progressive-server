# Step 395 — "Name function after command: list_local_users" (Conduit `50430cf`)

Source: [`timokoesters/conduit@50430cf`](https://github.com/timokoesters/conduit/commit/50430cf) (2022-01)

## What changed vs step 394

| Rust change | C++ translation |
|---|---|
| Name function after command: list_local_users. Function rename for clarity. | **No-op for us** — Rust function rename — our C++ uses get_local_users. |

## Implementation details

- Rust function rename — our C++ uses get_local_users.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
