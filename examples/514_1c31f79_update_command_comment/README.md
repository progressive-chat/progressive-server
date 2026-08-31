# Step 514 — "Update command comment to coincide with the default action" (Conduit `1c31f79`)

Source: [`timokoesters/conduit@1c31f79`](https://github.com/timokoesters/conduit/commit/1c31f79) (2022-06)

## What changed vs step 513

| Rust change | C++ translation |
|---|---|
| Update command comment to coincide with the default action. Documentation comment update. | **Skipped** — Comment only. |

## Implementation details

- Comment only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
