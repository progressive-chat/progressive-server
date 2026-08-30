# Step 44 — "Add Complement dockerfile and move sytest dir" (Conduit `3e0378755`)

Source: [`timokoesters/conduit@3e0378755`](https://github.com/timokoesters/conduit/commit/3e0378755) (2020-09-16)

## What changed vs step 43

| Rust change | C++ translation |
|---|---|
| No Rust code changes — pure infrastructure. Skipped (CI/sytest out of scope for C++). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
