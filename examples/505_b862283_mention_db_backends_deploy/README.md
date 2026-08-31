# Step 505 — "Mention different databse backends in DEPLOY.md" (Conduit `b862283`)

Source: [`timokoesters/conduit@b862283`](https://github.com/timokoesters/conduit/commit/b862283) (2022-06)

## What changed vs step 504

| Rust change | C++ translation |
|---|---|
| Mention different database backends in DEPLOY.md. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
