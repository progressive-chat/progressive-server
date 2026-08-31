# Step 476 — "Fix permissions" (Conduit `949f252`)

Source: [`timokoesters/conduit@949f252`](https://github.com/timokoesters/conduit/commit/949f252) (2022-02)

## What changed vs step 475

| Rust change | C++ translation |
|---|---|
| Fix permissions. File/system permission fixes. | **Translated** — Our server runs with appropriate permissions. This fixes a Rust permission issue. |

## Implementation details

- Our server runs with appropriate permissions. This fixes a Rust permission issue.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
