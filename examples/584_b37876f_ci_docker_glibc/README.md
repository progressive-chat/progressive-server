# Step 584 — "fix(ci): Only build in (remote host) docker and switch to glibc" (Conduit `b37876f`)

Source: [`timokoesters/conduit@b37876f`](https://github.com/timokoesters/conduit/commit/b37876f) (2022-11)

## What changed vs step 583

| Rust change | C++ translation |
|---|---|
| Fix(ci): Only build in (remote host) docker and switch to glibc. CI Docker build changes. 5 files changed. | **No-op for us** — Rust CI Docker — our C++ uses different CI. |

## Implementation details

- Rust CI Docker — our C++ uses different CI.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
