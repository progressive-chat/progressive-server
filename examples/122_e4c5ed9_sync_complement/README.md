# Step 122 — "Sync with newest complement changes" (Conduit `e4c5ed9`)

Source: [`timokoesters/conduit@e4c5ed9`](https://github.com/timokoesters/conduit/commit/e4c5ed9) (2020-11)

## What changed vs step 121

| Rust change | C++ translation |
|---|---|
| Sync with newest complement changes. | **Skipped** — Test infrastructure change. |

## Implementation details

- Test infrastructure change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
