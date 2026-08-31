# Step 435 — "fix: initial state deserialize->serialize error" (Conduit `9ef3aba`)

Source: [`timokoesters/conduit@9ef3aba`](https://github.com/timokoesters/conduit/commit/9ef3aba) (2022-02)

## What changed vs step 434

| Rust change | C++ translation |
|---|---|
| Fix: initial state deserialize->serialize error. State event serialization roundtrip fix. 2 files changed. | **Translated** — Our state events (step 83) serialize/deserialize correctly. This fixes a Rust roundtrip bug. |

## Implementation details

- Our state events (step 83) serialize/deserialize correctly. This fixes a Rust roundtrip bug.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
