# Step 3 — "database" (Conduit `c2c18b46`, 2020-02-20)

Source: [`timokoesters/conduit@c2c18b4`](https://github.com/timokoesters/conduit/commit/c2c18b46517c351bbd68ec2619231b46f384b5b2)
— the first persistence in the Conduit → conduwuit → tuwunel line.

## What changed vs step 2

| Rust change | C++ translation |
|---|---|
| `sled::open(data_dir)` — embedded LSM KV store | `stubdb::Db::open(dir)` — `std::map` + one `.kv` file per tree (`database.hpp/cpp`) |
| `rocket.manage(db)` / `State<Db>` DI | explicit `Context { stubdb::Db* }` passed to handlers |
| `db.open_tree("users")` | `ctx->db->open_tree("users")` returning a `Tree` handle |
| `users.contains_key(...)` / `users.insert(k, v)` | same method names on `stubdb::Tree` |
| new `ErrorKind::UserInUse` | `ruma::ErrorKind::UserInUse` → `"M_USER_IN_USE"` |
| register rejects taken IDs, then stores `(user_id, password)` **plaintext** | identical, plaintext included (hashing comes much later upstream) |
| new route `POST /_matrix/client/r0/login` | `login_route` + `LoginRequest` with nested/flattened identifier parsing |
| login ignores the password entirely; any password wins | faithfully reproduced |

The JSON reader also learned to descend into nested objects
(`JsonObject::object()`), needed for login's
`{"identifier":{"type":"m.id.user","user":"neo"}}`.

## Behavior

```console
$ curl -d '{"username":"neo","password":"redpill"}' -X POST .../r0/register
{"access_token":"randomtoken","device_id":"randomid","home_server":"localhost","user_id":"@neo:localhost"}

$ curl -d '{"username":"neo"}' -X POST .../r0/register        # again
{"errcode":"M_USER_IN_USE","error":"Desired user ID is already taken."}

$ curl -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"neo"},"password":"whatever"}' \
    -X POST .../r0/login                                       # any password works!
{"access_token":"randomtoken","device_id":"randomid","home_server":"localhost","user_id":"@neo:localhost"}

$ curl -d '{"identifier":{"type":"m.id.user","user":"trinity"}}' -X POST .../r0/login
{"errcode":"M_FORBIDDEN","error":"UserId not found."}
```

Persistence survives restarts: kill the server, start it again, registering
`neo` still returns `M_USER_IN_USE`. Data lives in `~/.local/share/conduit-step03/users.kv`
(the Rust original used `~/.local/share/matrixserver` via the `directories`
crate).

## Build & run

```console
$ cmake -B build -S . && cmake --build build && ./build/conduit_step03
# or:
$ g++ -std=c++23 -Wall -Wextra -Wpedantic main.cpp ruma_wrapper.cpp database.cpp -o conduit_step03
```

## C++ study notes

1. `std::function<void()> on_change_` in `Tree` is a poor-man's write hook —
   where sled fsyncs its write-ahead log. Compare with real storage engines:
   progressive-server uses SQLite/PostgreSQL, tuwunel RocksDB.
2. `static stubdb::Db db` in `main()` gives a stable address so handlers can
   borrow it through `Context*` without ownership questions.
3. Notice how little changed in the HTTP layer: persistence is a handler-level
   concern, which is exactly why the commit only touched `main.rs`.
