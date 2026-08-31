# Step 22 — "feat: implement password changing (#138)" (Conduit `67a1f21f`)

Source: [`timokoesters/conduit@67a1f21f`](https://github.com/timokoesters/conduit/commit/67a1f21f) (2020-07-02)

## What changed vs step 21

| Rust change | C++ translation |
|---|---|
| Adds `POST /account/password` route. `Data::set_password` updates the Argon2id hash; old tokens are removed; if `logout_devices` is true, all other device tokens are also removed. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
