# Step 300 — "Move the link to cross-compiling guide to DEPLOY.md" (Conduit `f199b51`)

Source: [`timokoesters/conduit@f199b51`](https://github.com/timokoesters/conduit/commit/f199b51) (2021-05)

## What changed vs step 299

| Rust change | C++ translation |
|---|---|
| Move the link to cross-compiling guide to DEPLOY.md. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
