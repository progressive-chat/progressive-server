# Step 744 — "add an engage file" (Conduit `e8ac881`)

Source: [`timokoesters/conduit@e8ac881`](https://github.com/timokoesters/conduit/commit/e8ac881) (2024-01)

## What changed vs step 743

| Rust change | C++ translation |
|---|---|
| Add an engage file. GitHub engage file for issue triage. | **Skipped** — GitHub config only. |

## Implementation details

- GitHub config only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
