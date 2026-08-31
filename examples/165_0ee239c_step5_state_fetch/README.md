# Step 165 — "Step 5 in /send just fetches state from incoming server" (Conduit `0ee239c`)

Source: [`timokoesters/conduit@0ee239c`](https://github.com/timokoesters/conduit/commit/0ee239c) (2021-01)

## What changed vs step 164

| Rust change | C++ translation |
|---|---|
| Step 5 in `/send` just fetches state from the incoming server. Refactor of the state resolution flow. | **Translated** — Our state resolution in step 83 does fetch state from incoming server. |

## Implementation details

- Our state resolution in step 83 does fetch state from incoming server.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
