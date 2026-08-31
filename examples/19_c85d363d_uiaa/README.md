# Step 19 — "feat: user interactive authentication" (Conduit `c85d363d`)

Source: [`timokoesters/conduit@c85d363d`](https://github.com/timokoesters/conduit/commit/c85d363d) (2020-06-08)

## What changed vs step 16

| Rust change | C++ translation |
|---|---|
| Adds UIAA: `database/uiaa.rs` with `Uiaa { userdeviceid_uiaainfo }` tree. `create(user, device, uiaainfo)` starts a session. `try_auth(...)` resumes by session token and completes `m.login.dummy` or `m.login.password` (Argon2id). `register_route` returns 401+flows+session for first attempt. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
