# Step 159 — "improvement: better deploy guide" (Conduit `b481871`)

Source: [`timokoesters/conduit@b481871`](https://github.com/timokoesters/conduit/commit/b481871) (2021-01)

## What changed vs step 158

| Rust change | C++ translation |
|---|---|
| Improvement: better deploy guide in README.md. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
