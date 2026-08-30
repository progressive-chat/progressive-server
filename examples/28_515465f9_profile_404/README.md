# Step 28 — "fix: make element not show "unknown user" warning" (Conduit `515465f9`)

Source: [`timokoesters/conduit@515465f9`](https://github.com/timokoesters/conduit/commit/515465f9) (2020-08-31)

## What changed vs step 27

| Rust change | C++ translation |
|---|---|
| Returns `M_NOT_FOUND` 404 from `GET /profile/{user_id}` when the user doesn't exist. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
