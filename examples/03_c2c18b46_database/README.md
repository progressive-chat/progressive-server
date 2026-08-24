# Step 3 — "database" (Conduit `c2c18b46`, 2020-02-20)

Source: [`timokoesters/conduit@c2c18b4`](https://github.com/timokoesters/conduit/commit/c2c18b46517c351bbd68ec2619231b46f384b5b2)
— first persistence in the lineage. Upstream plugged in **sled**; we plug in
**RocksDB** behind a sled-shaped adapter (`src/sled.hpp/cpp`) — column
families as trees, WAL durability included.

## What changed vs step 2

| Rust | C++ |
|---|---|
| `sled::open(data_dir)` | `sled::Db::open(dir)` → RocksDB with lazy column families |
| `rocket.manage(db)` / `State<Db>` DI | explicit `Context { sled::Db* }` |
| `db.open_tree("users")`, `contains_key`, `insert` | same calls on `sled::Tree` |
| register rejects taken IDs (`M_USER_IN_USE`), stores `(user_id, password)` **plaintext** | identical |
| new route `POST /login`; password ignored — any password wins | faithfully reproduced |

## Behavior

```console
$ curl -d '{"username":"neo","password":"redpill"}' -X POST .../r0/register   # ok
$ curl -d '{"username":"neo"}' -X POST .../r0/register                        # again
{"errcode":"M_USER_IN_USE","error":"Desired user ID is already taken."}
$ curl -d '{"identifier":{"type":"m.id.user","user":"trinity"}}' -X POST .../r0/login
{"errcode":"M_FORBIDDEN","error":"UserId not found."}
```

Persistence survives restarts. Data dir: `~/.local/share/conduit-step03`
(upstream used `~/.local/share/matrixserver`).

## C++ study notes

`sled::Tree::contains_key` maps to a RocksDB `Get` that ignores the value;
the adapter throws on non-OK statuses like `.unwrap()` would panic.
