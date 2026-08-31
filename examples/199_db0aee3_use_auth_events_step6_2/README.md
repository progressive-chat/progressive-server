# Step 199 — "Use the auth_events for step 6, WIP forward_extremity_ids fn" (Conduit `db0aee3`)

Source: [`timokoesters/conduit@db0aee3`](https://github.com/timokoesters/conduit/commit/db0aee3) (2021-02)

## What changed vs step 198

| Rust change | C++ translation |
|---|---|
| Use the `auth_events` for step 6 in `/send`, WIP `forward_extremity_ids` fn. Duplicate of step 173 (96dc6be). | **Translated** — Our state-res uses `auth_events` for step 6. |

## Implementation details

- Our state-res uses `auth_events` for step 6.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
