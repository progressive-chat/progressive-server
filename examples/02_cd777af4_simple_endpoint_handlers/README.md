# Step 2 — "feat: simple endpoint handlers" (Conduit `cd777af4`)

Source: [`timokoesters/conduit@cd777af4`](https://github.com/timokoesters/conduit/commit/cd777af4) (2020-02-18)

## What changed vs step 1

| Rust change | C++ translation |
|---|---|
| Adds 4 client-server endpoints: `/versions`, `/directory/room/{alias}`, `/rooms/{id}/join`, `/rooms/{id}/send/{type}/{txnid}`. Introduces `MatrixResult<T>` responder and M_NOT_FOUND/M_INVALID_USERNAME errors. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
