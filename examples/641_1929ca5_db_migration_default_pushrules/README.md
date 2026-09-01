# Step 641 — "Add a database migration to fix and update the default pushrules" (Conduit `1929ca5`)

Source: [`timokoesters/conduit@1929ca5`](https://github.com/timokoesters/conduit/commit/1929ca5) (2023-03)

## What changed vs step 640

| Rust change | C++ translation |
|---|---|
| Add a database migration to fix and update the default pushrules. Migration for push rules. 1 file changed. | **Translated** — Related to step 310 (migrations). This adds push rule migration. |

## Implementation details

- Related to step 310 (migrations). This adds push rule migration.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
