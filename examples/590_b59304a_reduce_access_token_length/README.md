# Step 590 — "Reduce length of generated access tokens and session ids" (Conduit `b59304a`)

Source: [`timokoesters/conduit@b59304a`](https://github.com/timokoesters/conduit/commit/b59304a) (2022-11)

## What changed vs step 589

| Rust change | C++ translation |
|---|---|
| Reduce length of generated access tokens and session ids. Shorter tokens for efficiency. 1 file changed. | **Translated** — Our tokens (step 13) are standard length. This shortens them in Rust. |

## Implementation details

- Our tokens (step 13) are standard length. This shortens them in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
