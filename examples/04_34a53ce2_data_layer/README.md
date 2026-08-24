# Step 4 — "Better database structure" (Conduit `34a53ce2`, 2020-03-28)

Source: [`timokoesters/conduit@34a53ce2`](https://github.com/timokoesters/conduit/commit/34a53ce2)
— invents Conduit's **Data layer**: handlers stop touching the DB and call
named domain methods instead. The pattern survives in conduwuit's `Database`,
tuwunel's `Data`/`Store`, and progressive-server's `storage::`.

## Deltas vs step 3

| Rust | C++ |
|---|---|
| new `src/data.rs`: `Data(sled::Db)`, `load_or_create`, `set_hostname`/`hostname` (sled root tree), `user_exists`/`user_add` on tree `username_password` | `src/data.{hpp,cpp}`, identical method names |
| handlers get `State<Data>`; tree names vanish from main.rs | `Context { Data* }` |
| hostname stored in DB, appended to user ids; register echoes it as home_server | identical |
| login accepts full `"@user:server"` or bare localpart; malformed ids → `M_UNKNOWN` | same error mapping |
| versions list r0.0.1…r0.6.0 + `unstable_features` | identical |

## C++ study notes

Rust's `let users` binding is immutable yet `insert()` works — interior
mutability. In C++ the Tree handle is simply non-const.
