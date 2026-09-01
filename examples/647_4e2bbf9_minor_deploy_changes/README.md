# Step 647 — "Minor DEPLOY.md changes" (Conduit `4e2bbf9`)

Source: [`timokoesters/conduit@4e2bbf9`](https://github.com/timokoesters/conduit/commit/4e2bbf9) (2023-05)

## What changed vs step 646

| Rust change | C++ translation |
|---|---|
| Minor DEPLOY.md changes. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
