# Step 660 — "Do state res even if the event soft fails" (Conduit `7c6d25d`)

Source: [`timokoesters/conduit@7c6d25d`](https://github.com/timokoesters/conduit/commit/7c6d25d) (2023-06)

## What changed vs step 659

| Rust change | C++ translation |
|---|---|
| Do state res even if the event soft fails. State resolution for soft-failed events. 1 file changed. | **Translated** — Our state resolution (step 83) handles soft fails. This ensures it runs in Rust. |

## Implementation details

- Our state resolution (step 83) handles soft fails. This ensures it runs in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
