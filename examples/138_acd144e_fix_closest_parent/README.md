# Step 138 — "Fix get_closest_parent and cleanup federation/send/:txn" (Conduit `acd144e`)

Source: [`timokoesters/conduit@acd144e`](https://github.com/timokoesters/conduit/commit/acd144e) (2020-12)

## What changed vs step 137

| Rust change | C++ translation |
|---|---|
| Fix `get_closest_parent` and cleanup federation/send/:txn. Review feedback. | **No-op for us** — Our `federation_send_to_remotes` doesn't use `closest_parent` — it uses `pdu_leaves_replace`. |

## Implementation details

- Our `federation_send_to_remotes` doesn't use `closest_parent` — it uses `pdu_leaves_replace`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
