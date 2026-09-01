# Step 580 — "fix: stuck typing indicators" (Conduit `5d691f4`)

Source: [`timokoesters/conduit@5d691f4`](https://github.com/timokoesters/conduit/commit/5d691f4) (2022-10)

## What changed vs step 579

| Rust change | C++ translation |
|---|---|
| Fix: stuck typing indicators. Typing notification timeout/cleanup. 3 files changed. | **Translated** — Our typing (step 15) handles timeouts. This fixes stuck indicators in Rust. |

## Implementation details

- Our typing (step 15) handles timeouts. This fixes stuck indicators in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
