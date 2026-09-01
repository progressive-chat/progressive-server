# Step 694 — "relax recovery mode" (Conduit `9fb8498`)

Source: [`timokoesters/conduit@9fb8498`](https://github.com/timokoesters/conduit/commit/9fb8498) (2023-07)

## What changed vs step 693

| Rust change | C++ translation |
|---|---|
| Relax recovery mode. Recovery mode behavior changes. 1 file changed. | **Translated** — Our server doesn't have recovery mode. This relaxes it in Rust. |

## Implementation details

- Our server doesn't have recovery mode. This relaxes it in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
