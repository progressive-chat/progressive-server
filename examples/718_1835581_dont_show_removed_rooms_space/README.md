# Step 718 — "fix: don't show removed rooms in space" (Conduit `1835581`)

Source: [`timokoesters/conduit@1835581`](https://github.com/timokoesters/conduit/commit/1835581) (2023-08)

## What changed vs step 717

| Rust change | C++ translation |
|---|---|
| Fix: don't show removed rooms in space. Space hierarchy excludes removed rooms. 1 file changed. | **Translated** — Follows step 667 (space hierarchies). Excludes removed rooms from spaces. |

## Implementation details

- Follows step 667 (space hierarchies). Excludes removed rooms from spaces.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
