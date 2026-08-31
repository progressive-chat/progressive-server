# Step 213 — "Move comments about Rooms trees to doc comments" (Conduit `f3253f2`)

Source: [`timokoesters/conduit@f3253f2`](https://github.com/timokoesters/conduit/commit/f3253f2) (2021-02)

## What changed vs step 212

| Rust change | C++ translation |
|---|---|
| Move comments about Rooms trees to doc comments. Code documentation cleanup. | **No-op for us** — Documentation only — no code change. |

## Implementation details

- Documentation only — no code change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
