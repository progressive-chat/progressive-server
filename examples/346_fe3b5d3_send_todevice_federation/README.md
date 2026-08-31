# Step 346 — "feat: send to-device events over federation" (Conduit `fe3b5d3`)

Source: [`timokoesters/conduit@fe3b5d3`](https://github.com/timokoesters/conduit/commit/fe3b5d3) (2021-07)

## What changed vs step 345

| Rust change | C++ translation |
|---|---|
| Feat: send to-device events over federation. To-device messaging (for encryption) across servers. 3 files changed. MAJOR encryption feature. | **Translated** — We don't have to-device events yet (step 301 started this). This adds federation sending. |

## Implementation details

- We don't have to-device events yet (step 301 started this). This adds federation sending.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
