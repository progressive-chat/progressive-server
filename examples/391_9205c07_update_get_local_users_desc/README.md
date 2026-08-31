# Step 391 — "Update get_local_users description" (Conduit `9205c07`)

Source: [`timokoesters/conduit@9205c07`](https://github.com/timokoesters/conduit/commit/9205c07) (2022-01)

## What changed vs step 390

| Rust change | C++ translation |
|---|---|
| Update get_local_users description. Documentation update. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
