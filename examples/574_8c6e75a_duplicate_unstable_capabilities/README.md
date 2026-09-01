# Step 574 — "Mark unstable versions as unstable in /capabilities" (Conduit `8c6e75a`)

Source: [`timokoesters/conduit@8c6e75a`](https://github.com/timokoesters/conduit/commit/8c6e75a) (2022-10)

## What changed vs step 573

| Rust change | C++ translation |
|---|---|
| Duplicate of step 551 (mark unstable versions in capabilities). | **Skipped** — Duplicate of step 551. |

## Implementation details

- Duplicate of step 551.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
