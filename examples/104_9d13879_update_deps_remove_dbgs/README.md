# Step 104 — "Update dependencies, remove dbgs" (Conduit `9d13879`)

Source: [`timokoesters/conduit@9d13879`](https://github.com/timokoesters/conduit/commit/9d13879) (2020-10)

## What changed vs step 103

| Rust change | C++ translation |
|---|---|
| Updates 5 dependencies and removes `dbg!()` macros (replace with `error!`). | **Skipped** — Mixed: dep update + Rust debug macro removal. |

## Implementation details

- Mixed: dep update + Rust debug macro removal.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
