# Step 544 — "fix: fluffychat login works again" (Conduit `fdd64fc`)

Source: [`timokoesters/conduit@fdd64fc`](https://github.com/timokoesters/conduit/commit/fdd64fc) (2022-10)

## What changed vs step 543

| Rust change | C++ translation |
|---|---|
| Fix: fluffychat login works again. Client login compatibility fix. 2 files changed. | **Translated** — Our login (step 13) works with FluffyChat. This fixes a Rust regression. |

## Implementation details

- Our login (step 13) works with FluffyChat. This fixes a Rust regression.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
