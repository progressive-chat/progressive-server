# Step 593 — "The procMacro option has long been on by default" (Conduit `7fd5b22`)

Source: [`timokoesters/conduit@7fd5b22`](https://github.com/timokoesters/conduit/commit/7fd5b22) (2022-12)

## What changed vs step 592

| Rust change | C++ translation |
|---|---|
| The procMacro option has long been on by default. Rust feature flag default. | **No-op for us** — Rust feature flag — N/A for C++. |

## Implementation details

- Rust feature flag — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
