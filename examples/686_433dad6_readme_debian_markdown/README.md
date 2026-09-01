# Step 686 — "Turn README.Debian into a markdown file" (Conduit `433dad6`)

Source: [`timokoesters/conduit@433dad6`](https://github.com/timokoesters/conduit/commit/433dad6) (2023-07)

## What changed vs step 685

| Rust change | C++ translation |
|---|---|
| Turn README.Debian into a markdown file. Documentation format change. 3 files changed. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
