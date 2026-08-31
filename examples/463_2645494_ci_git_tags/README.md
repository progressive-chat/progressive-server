# Step 463 — "fix(ci): Also run CI for git tags" (Conduit `2645494`)

Source: [`timokoesters/conduit@2645494`](https://github.com/timokoesters/conduit/commit/2645494) (2022-02)

## What changed vs step 462

| Rust change | C++ translation |
|---|---|
| Fix(ci): Also run CI for git tags. CI trigger on tags. | **No-op for us** — Rust CI — N/A for C++. |

## Implementation details

- Rust CI — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
