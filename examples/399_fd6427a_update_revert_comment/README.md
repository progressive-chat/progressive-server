# Step 399 — "Update/Revert code comment" (Conduit `fd6427a`)

Source: [`timokoesters/conduit@fd6427a`](https://github.com/timokoesters/conduit/commit/fd6427a) (2022-01)

## What changed vs step 398

| Rust change | C++ translation |
|---|---|
| Update/Revert code comment. Documentation only. | **Skipped** — Comment only. |

## Implementation details

- Comment only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
