# Step 89 — "fix(service/media): create directory for media file only on new file creation" (Conduit `1f7f74a`)

Source: [`timokoesters/conduit@1f7f74a`](https://github.com/timokoesters/conduit/commit/1f7f74a)

This step changes the media file creation logic to only create parent directories when using the "Deep" directory structure (from MSC4291's deep hashed directory structure). Previously, directories were created unconditionally.

## What changed vs step 86

| Rust change | C++ translation |
|---|---|
| Only create directories when `DirectoryStructure::Deep` is used | **No-op** — our media is stored in RocksDB, not on the filesystem |

## Implementation details

Our media implementation stores all media in a RocksDB database (`mediaid_file` and `mediaid_meta` trees), not on the filesystem. There are no filesystem directories to create. This commit only affects filesystem-based media storage, which we don't use.

## Smoke test

No behavioral change — media upload/download continues to work as before.