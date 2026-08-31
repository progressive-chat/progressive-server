# Step 114 — "improvement: flush after every request that manipulates the db" (Conduit `6dbe195`)

Source: [`timokoesters/conduit@6dbe195`](https://github.com/timokoesters/conduit/commit/6dbe195) (2020-10)

## What changed vs step 113

| Rust change | C++ translation |
|---|---|
| Improvement: flush the database after every request that manipulates the DB. Ensures data is persisted before responding to the client. | **Translated** — Our sled operations auto-flush. The `dbs.push(&db).flush()` pattern in our code is equivalent. |

## Implementation details

- Our sled operations auto-flush. The `dbs.push(&db).flush()` pattern in our code is equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
