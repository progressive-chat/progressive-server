# Step 473 — "improve docker documentation some" (Conduit `94573a3`)

Source: [`timokoesters/conduit@94573a3`](https://github.com/timokoesters/conduit/commit/94573a3) (2022-02)

## What changed vs step 472

| Rust change | C++ translation |
|---|---|
| Improve docker documentation some. Docker docs. 4 files changed. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
