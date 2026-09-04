# Step 769 — knocking

Source: [`timokoesters/conduit@21af83e`](https://github.com/timokoesters/conduit/commit/21af83e) (2025-03-03)

## What changed vs step 768

| Rust change | C++ translation |
|---|---|
| Adds `POST /rooms/{id}/knock` and the membership `knock` state; `Data::is_knocked` helper; federation `make_knock`/`send_knock` stubs. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
