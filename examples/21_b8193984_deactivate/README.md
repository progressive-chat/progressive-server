# Step 21 — "feat: account deactivation (#137)" (Conduit `b8193984`)

Source: [`timokoesters/conduit@b8193984`](https://github.com/timokoesters/conduit/commit/b8193984) (2020-07-05)

## What changed vs step 20

| Rust change | C++ translation |
|---|---|
| Adds `POST /account/deactivate` route. `Data::deactivate_account` sets the `deactivated` flag; login is rejected with M_USER_DEACTIVATED; `user_directory` search filters out deactivated users. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
