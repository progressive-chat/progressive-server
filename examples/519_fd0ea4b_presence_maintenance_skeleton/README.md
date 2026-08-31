# Step 519 — "feat(database/presence): add skeleton for presence maintenance" (Conduit `fd0ea4b`)

Source: [`timokoesters/conduit@fd0ea4b`](https://github.com/timokoesters/conduit/commit/fd0ea4b) (2022-10)

## What changed vs step 518

| Rust change | C++ translation |
|---|---|
| Feat(database/presence): add skeleton for presence maintenance. Presence system skeleton. 1 file changed. | **Translated** — We don't have presence yet (gap from 2020). This adds the skeleton in Rust. |

## Implementation details

- We don't have presence yet (gap from 2020). This adds the skeleton in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
