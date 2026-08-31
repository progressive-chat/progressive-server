# Step 478 — "Fix proxy config examples in config/proxy.rs" (Conduit `65fa4b2`)

Source: [`timokoesters/conduit@65fa4b2`](https://github.com/timokoesters/conduit/commit/65fa4b2) (2022-02)

## What changed vs step 477

| Rust change | C++ translation |
|---|---|
| Fix proxy config examples in config/proxy.rs. Documentation fix for proxy configuration. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
