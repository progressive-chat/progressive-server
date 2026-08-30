# Step 24 — "Merge pull request 'Room visibility, aliases and redaction' (#40) from alias into master" (Conduit `3aa0c8ed`)

Source: [`timokoesters/conduit@3aa0c8ed`](https://github.com/timokoesters/conduit/commit/3aa0c8ed) (2020-05-31)

## What changed vs step 23

| Rust change | C++ translation |
|---|---|
| Adds `set_alias`, `remove_alias`, `id_from_alias`, room visibility filter in `createRoom`, and aliases search. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
