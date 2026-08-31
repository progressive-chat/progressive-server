# Step 173 — "Use the auth_events for step 6, WIP forward_extremity_ids fn" (Conduit `96dc6be`)

Source: [`timokoesters/conduit@96dc6be`](https://github.com/timokoesters/conduit/commit/96dc6be) (2021-01)

## What changed vs step 172

| Rust change | C++ translation |
|---|---|
| Use the `auth_events` for step 6 in `/send`, WIP `forward_extremity_ids` fn. | **Translated** — Our state-res (step 83) uses `auth_events` for step 6 (the auth check). |

## Implementation details

- Our state-res (step 83) uses `auth_events` for step 6 (the auth check).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
