# Step 368 — "fix: auth event fetch order" (Conduit `5bcc132`)

Source: [`timokoesters/conduit@5bcc132`](https://github.com/timokoesters/conduit/commit/5bcc132) (2022-01)

## What changed vs step 367

| Rust change | C++ translation |
|---|---|
| Fix: auth event fetch order. Correct ordering of auth chain events. | **Translated** — Our auth chain uses proper order. This fixes the Rust version. |

## Implementation details

- Our auth chain uses proper order. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
