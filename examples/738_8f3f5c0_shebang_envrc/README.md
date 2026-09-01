# Step 738 — "add shebang to .envrc" (Conduit `8f3f5c0`)

Source: [`timokoesters/conduit@8f3f5c0`](https://github.com/timokoesters/conduit/commit/8f3f5c0) (2023-12)

## What changed vs step 737

| Rust change | C++ translation |
|---|---|
| Add shebang to .envrc. Shell script shebang. | **Skipped** — Shell script only. |

## Implementation details

- Shell script only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
