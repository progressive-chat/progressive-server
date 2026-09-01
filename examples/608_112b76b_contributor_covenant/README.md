# Step 608 — "Add Contributor's Covenant Code of Conduct" (Conduit `112b76b`)

Source: [`timokoesters/conduit@112b76b`](https://github.com/timokoesters/conduit/commit/112b76b) (2023-01)

## What changed vs step 607

| Rust change | C++ translation |
|---|---|
| Add Contributor's Covenant Code of Conduct. Community guidelines. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
