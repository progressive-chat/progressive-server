# Step 369 — "feat: lazy loading" (Conduit `68e910b`)

Source: [`timokoesters/conduit@68e910b`](https://github.com/timokoesters/conduit/commit/68e910b) (2022-01)

## What changed vs step 368

| Rust change | C++ translation |
|---|---|
| Feat: lazy loading. Lazy load room data on demand. 5 files changed. MAJOR feature. | **Translated** — We don't have lazy loading yet. This adds on-demand room loading. |

## Implementation details

- We don't have lazy loading yet. This adds on-demand room loading.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
