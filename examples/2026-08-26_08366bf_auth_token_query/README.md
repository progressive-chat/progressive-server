# 2026-tail — "fix: only allow request to pass auth with token query if auth type is None" (Conduit `08366bf`)

Source: [`timokoesters/conduit@08366bf`](https://github.com/timokoesters/conduit/commit/08366bf) (2026-08-26)

## What changed vs step 93 (last numbered step)

| Rust change | C++ translation |
|---|---|
| `openid/request_token` enforces `body.user_id == sender_user`; `extract_token` prefers Authorization header over `?access_token=`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
