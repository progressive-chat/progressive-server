# Step 419 — "Do not copy mxc string unnecessarily in db.get_thumbnail()" (Conduit `529e88c`)

Source: [`timokoesters/conduit@529e88c`](https://github.com/timokoesters/conduit/commit/529e88c) (2022-01)

## What changed vs step 418

| Rust change | C++ translation |
|---|---|
| Do not copy mxc string unnecessarily in db.get_thumbnail(). String copy optimization. 2 files changed. | **Translated** — Our thumbnail handling (step 14) avoids unnecessary copies. This fixes the Rust version. |

## Implementation details

- Our thumbnail handling (step 14) avoids unnecessary copies. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
