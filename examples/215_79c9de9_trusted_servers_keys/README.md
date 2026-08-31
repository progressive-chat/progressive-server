# Step 215 — "Add trusted_servers, filter servers to query keys by trusted_servers" (Conduit `79c9de9`)

Source: [`timokoesters/conduit@79c9de9`](https://github.com/timokoesters/conduit/commit/79c9de9) (2021-03)

## What changed vs step 214

| Rust change | C++ translation |
|---|---|
| Add `trusted_servers`, filter servers to query keys by trusted_servers. Only query keys from servers we trust. | **Translated** — Our key fetching (step 8) queries from origin. Adding trusted_servers config would be new. |

## Implementation details

- Our key fetching (step 8) queries from origin. Adding trusted_servers config would be new.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
