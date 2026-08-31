# Step 53 — "fix: permission checks for aliases" (Conduit `144d548`)

Source: [`timokoesters/conduit@144d548`](https://github.com/timokoesters/conduit/commit/144d548) (2024-06-12)

## What changed vs step 52

| Rust change | C++ translation |
|---|---|
| `set_alias` checks the user has the power level to set state events (m.room.canonical_alias, m.room.aliases). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
