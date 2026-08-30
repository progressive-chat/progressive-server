# Step 3 — "feat: database" (Conduit `c2c18b46`)

Source: [`timokoesters/conduit@c2c18b46`](https://github.com/timokoesters/conduit/commit/c2c18b46) (2020-02-20)

## What changed vs step 2

| Rust change | C++ translation |
|---|---|
| Adds the sled-based database layer with a `users` tree for user records. Adds the `/login` route that checks username+password against the `users` tree; M_USER_IN_USE for duplicate registration. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
