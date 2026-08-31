# Step 102 — "feat: federation disabled by default" (Conduit `6afc4c9`)

Source: [`timokoesters/conduit@6afc4c9`](https://github.com/timokoesters/conduit/commit/6afc4c9) (2020-10)

## What changed vs step 101

| Rust change | C++ translation |
|---|---|
| Adds the `allow_federation` config option. Federation is now disabled by default (opt-in via config). | **No-op for us** — Our federation is always enabled. Config layer (step 99) doesn't exist yet. |

## Implementation details

- Our federation is always enabled. Config layer (step 99) doesn't exist yet.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
