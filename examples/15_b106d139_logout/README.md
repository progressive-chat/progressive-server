# Step 15 — "Add logout route and database methods" (Conduit `b106d139`, 2020-05-24, PR #21)

Source: [`timokoesters/conduit@b106d139`](https://github.com/timokoesters/conduit/commit/b106d139)

## What changed vs step 14

| Rust change | C++ translation |
|---|---|
| `POST /_matrix/client/r0/logout` — resolves the authenticated user+device and calls `remove_device` | route added; our token→user lookup plus device scan finds the bound device |
| `database/users.rs remove_device`: removes `userdeviceid_devicekeys`, the `userdeviceid_token` entry + reverse `token_userdeviceid`, to-device events (scan_prefix), then the device entry | adapted to our trees: erases `userdeviceid_token[user\xffdevice]`, `token_userid[token]`, and the device from `userid_deviceids` (`Data::remove_device_by_token`) |
| TODO upstream: one-time keys not yet removed | equally TODO here |

## Verified

```
register → tokenA; login → tokenB (different)
sync(tokenA)=200 · sync(tokenB)=200
logout(tokenB)={} [200]
sync(tokenB)=401          ← invalidated
sync(tokenA)=200          ← other sessions survive
logout(tokenB) again=401  ← double-logout safe
```

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
