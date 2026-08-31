# Step 502 — "Adding a hint to closed ports in the testing section" (Conduit `58d784a`)

Source: [`timokoesters/conduit@58d784a`](https://github.com/timokoesters/conduit/commit/58d784a) (2022-06)

## What changed vs step 501

| Rust change | C++ translation |
|---|---|
| Adding a hint to closed ports in the testing section. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
