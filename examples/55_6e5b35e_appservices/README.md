# Step 55 — "feat: implement appservices" (Conduit `6e5b35e`)

Source: [`timokoesters/conduit@6e5b35e`](https://github.com/timokoesters/conduit/commit/6e5b35e) (2020-12-08)

## What changed vs step 54

| Rust change | C++ translation |
|---|---|
| **New `appservice_server.rs`** - appservice request handling | **Translated** - New `appservice_server.hpp/cpp` |
| **Appservice registration API** | **Translated** - Admin endpoint for appservice registration |
| **Appservice transaction handling** | **Translated** - `/send/txn` appservice support |
| **Appservice user/room management** | **Translated** - Appservice user/room creation |
| **Appservice webhook/transaction handling** | **Translated** - Transaction endpoints |

## Implementation details

1. **New `appservice_server` module** - Handles appservice HTTP requests
2. **Appservice registration** - Admin can register appservices with `hs_token` and `as_token`
3. **Transaction handling** - Process appservice transactions with proper auth
4. **Appservice user/room management** - Appservices can create users/rooms
5. **Transaction ID handling** - Proper deduplication for appservice transactions

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
