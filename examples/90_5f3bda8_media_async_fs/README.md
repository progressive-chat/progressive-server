# Step 90 — "refactor(service/media): make all fs operations async" (Conduit `5f3bda8`)

Source: [`timokoesters/conduit@5f3bda8`](https://github.com/timokoesters/conduit/commit/5f3bda8)

This step refactors all filesystem operations in the media service to be async (using `tokio::fs` and `futures_util`). 

## What changed vs step 86

| Rust change | C++ translation |
|---|---|
| `fs::create_dir_all` → `fs::create_dir_all().await` | **No-op** — our media is stored in RocksDB, not on the filesystem |
| `purge_files` made async | No-op |
| `purge_files`, `purge_from_user`, `purge_from_server`, `clear_required_space` made async | No-op |

## Implementation details

Our media implementation stores all media in a RocksDB database (`mediaid_file` and `mediaid_meta` trees), not on the filesystem. There are no filesystem operations to make async. This commit only affects filesystem-based media storage, which we don't use.

## Smoke test

No behavioral change — media upload/download continues to work as before.