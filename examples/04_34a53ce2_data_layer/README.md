# Step 4 — "Better database structure" (Conduit `34a53ce2`, 2020-03-28)

Source: [`timokoesters/conduit@34a53ce2`](https://github.com/timokoesters/conduit/commit/34a53ce2)
— the commit that invented Conduit's **Data layer**, the pattern that survives
in conduwuit's `Database`, tuwunel's `Data`/`Store`, and progressive-server's
`storage::`.

(Skipped upstream, nothing to translate: `6fffcecf` dep bump, `1679da77`
RUST_LOG default, `6d27f155` more logging, `744e0adf` WIP auth.)

## What changed vs step 3

| Rust change | C++ translation |
|---|---|
| new module `src/data.rs`: `pub struct Data(sled::Db)` | new files `data.hpp/cpp`: `class Data { stubdb::Db db_; }` |
| handlers get `State<Data>` instead of `State<Db>`; tree names vanish from main.rs | `Context { Data* }`; `open_tree()` calls live only inside `data.cpp` now |
| tree renamed `"users"` → `"username_password"` | same rename, visible in `data.cpp` only |
| `Data::load_or_create()`, `set_hostname()`, `hostname()` — hostname stored in sled's default (root) tree | `stubdb::Db::insert_root/get_root`, persisted in `_root.kv` |
| user IDs built as `@{localpart}:{hostname}` from the DB; register echoes `home_server: data.hostname()` | identical |
| login accepts full `"@user:server"` or bare localpart; malformed full IDs → `M_UNKNOWN` "Bad login type." (was implicit M_FORBIDDEN path) | `full_user_id_valid()` + same error mapping |
| versions response: `r0.0.1`…`r0.6.0` + new `unstable_features` map (empty) | 7-entry vector + `{}` object |
| `debug!()` calls ("ID already taken", "Invalid UserId.", …) | `[debug]` printf lines |

Still unchanged upstream: passwords plaintext, login ignores the password,
login response hardcodes `home_server: Some("localhost")`.

## Behavior

```console
$ curl http://127.0.0.1:8000/_matrix/client/versions
{"versions":["r0.0.1","r0.1.0","r0.2.0","r0.3.0","r0.4.0","r0.5.0","r0.6.0"],"unstable_features":{}}

$ curl -d '{"username":"neo"}' -X POST .../r0/register
{"access_token":"randomtoken","device_id":"randomid","home_server":"localhost","user_id":"@neo:localhost"}

$ curl -d '{"identifier":{"type":"m.id.user","user":"@neo:localhost"}}' -X POST .../r0/login   # full id works now
{"access_token":"randomtoken","device_id":"randomid","home_server":"localhost","user_id":"@neo:localhost"}

$ curl -d '{"identifier":{"type":"m.id.user","user":"bad:user"}}' -X POST .../r0/login          # malformed id
{"errcode":"M_UNKNOWN","error":"Bad login type."}
```

Server log shows the new debug traces (`[debug] ID already taken`, etc.).

## Build & run

```console
$ cmake -B build -S . && cmake --build build && ./build/conduit_step04
# or:
$ g++ -std=c++23 -Wall -Wextra *.cpp -o conduit_step04
```

## C++ study notes

1. The layering move: after this commit, `main.cpp` contains zero storage
   calls. Compare `grep open_tree main.cpp` between steps 3 and 4.
2. Root-vs-named trees mirror sled's design; RocksDB (tuwunel) instead uses
   column families for the same idea.
3. `mutable root_` / const `get_root()` shows where logical constness beats
   bitwise constness when a cache is involved.
