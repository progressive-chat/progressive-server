# Step 812 — "Sqlite" config surface (Conduit `9d4fa9a2`)

Source: [`timokoesters/conduit@9d4fa9a2`](https://github.com/timokoesters/conduit/commit/9d4fa9a2) (2021-07-14)

Upstream makes the storage engine swappable (`sled` / `rocksdb` / `sqlite`
behind a `DatabaseEngine` trait + `DatabaseGuard`) and, alongside it,
replaces the `cache_capacity` config key (bytes, 1GB default) with
`db_cache_capacity_mb` (200MB default), warning on the deprecated key.

## What changed vs step 811

| Rust change | C++ translation |
|---|---|
| **`cache_capacity` → `db_cache_capacity_mb` (default 200.0)** | **Implemented** — `Data::load_or_create(dir, db_cache_capacity_mb = 200.0)` and `--db-cache-capacity-mb` flag (this port has no TOML layer; flags are its config surface). Non-positive / unparsable values fall back to the default with a warning |
| **DB cache actually honors the setting** | **Implemented** — the value sizes a shared RocksDB LRU block cache (`BlockBasedTableOptions`) applied to every column family, existing and lazily created. (The old parameter was accepted but ignored — see the removed `TODO` in `Data::Data`) |
| **Swappable `sled`/`rocksdb`/`sqlite` engine + `DatabaseGuard`** | **No counterpart** — this port is RocksDB-only by design (a `sled`-API adapter over RocksDB column families, matching what conduwuit migrated to); there are no lock-guard request handlers here |
| **`warn_deprecated` for the old `cache_capacity` key** | **No counterpart** — warns on a TOML key, and this port has no TOML config |
| **Sled-vs-sqlite directory detection / migration error** | **No counterpart** — single backend, nothing to migrate |
| **Per-route `State<Arc<Database>>` → `DatabaseGuard` churn** | **No counterpart** — mechanical guard-type swap, no behavior change |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit812
$ ./build/server --db-cache-capacity-mb 50 --port 8001 --data-dir /tmp/conduit812b
```
