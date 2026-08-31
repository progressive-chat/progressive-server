# Step 162 — "fix: update binary file name in docs for consistency" (Conduit `c263e13`)

Source: [`timokoesters/conduit@c263e13`](https://github.com/timokoesters/conduit/commit/c263e13) (2021-01)

## What changed vs step 161

| Rust change | C++ translation |
|---|---|
| Fix: update binary file name in docs for consistency. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
