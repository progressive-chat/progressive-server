# Step 472 — "feat(ci): Add dependency audit to CI tests" (Conduit `ad6eb92`)

Source: [`timokoesters/conduit@ad6eb92`](https://github.com/timokoesters/conduit/commit/ad6eb92) (2022-02)

## What changed vs step 471

| Rust change | C++ translation |
|---|---|
| Feat(ci): Add dependency audit to CI tests. Security audit in CI. | **No-op for us** — Rust CI security audit — N/A for C++. |

## Implementation details

- Rust CI security audit — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
