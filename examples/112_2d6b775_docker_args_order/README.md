# Step 112 — "Fix order of docker command arguments and change repository link to..." (Conduit `2d6b775`)

Source: [`timokoesters/conduit@2d6b775`](https://github.com/timokoesters/conduit/commit/2d6b775) (2020-10)

## What changed vs step 111

| Rust change | C++ translation |
|---|---|
| Fix: docker command argument order and update repository link. | **Skipped** — Pure Docker infrastructure fix. |

## Implementation details

- Pure Docker infrastructure fix.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
