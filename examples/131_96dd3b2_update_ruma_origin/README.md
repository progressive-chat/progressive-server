# Step 131 — "Update ruma to latest, fix unstable origin feature in ruma" (Conduit `96dd3b2`)

Source: [`timokoesters/conduit@96dd3b2`](https://github.com/timokoesters/conduit/commit/96dd3b2) (2020-12)

## What changed vs step 130

| Rust change | C++ translation |
|---|---|
| Update ruma to latest, fix unstable origin feature in ruma. | **Skipped** — Pure Rust dependency update. |

## Implementation details

- Pure Rust dependency update.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
