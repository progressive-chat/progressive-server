# Step 753 — "push oci image and x86_64-*-gnu build to bin cache" (Conduit `5cc53c9`)

Source: [`timokoesters/conduit@5cc53c9`](https://github.com/timokoesters/conduit/commit/5cc53c9) (2024-01)

## What changed vs step 752

| Rust change | C++ translation |
|---|---|
| Push oci image and x86_64-*-gnu build to bin cache. Multi-arch binary cache. 2 files changed. | **Skipped** — CI only. |

## Implementation details

- CI only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
