# Step 392 — "Updated function documentation" (Conduit `3e79d15`)

Source: [`timokoesters/conduit@3e79d15`](https://github.com/timokoesters/conduit/commit/3e79d15) (2022-01)

## What changed vs step 391

| Rust change | C++ translation |
|---|---|
| Updated function documentation. More documentation updates. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
