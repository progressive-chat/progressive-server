# Step 238 — "fix: move back to sled stable" (Conduit `044e65a`)

Source: [`timokoesters/conduit@044e65a`](https://github.com/timokoesters/conduit/commit/044e65a) (2021-04)

## What changed vs step 237

| Rust change | C++ translation |
|---|---|
| Fix: move back to sled stable. Database engine version change. | **No-op for us** — Our sled usage is on stable. This is a Rust dependency version change. |

## Implementation details

- Our sled usage is on stable. This is a Rust dependency version change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
