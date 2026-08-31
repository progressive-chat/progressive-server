# Step 501 — "Add a section to Ports and forwarding" (Conduit `ae8e143`)

Source: [`timokoesters/conduit@ae8e143`](https://github.com/timokoesters/conduit/commit/ae8e143) (2022-06)

## What changed vs step 500

| Rust change | C++ translation |
|---|---|
| Add a section to Ports and forwarding. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
