# Step 665 — "update example configurations in DEPLOY.md for Apache and Nginx which include upstream proxy timeouts of 5 minutes to allow for room joins which take a while" (Conduit `dc50197`)

Source: [`timokoesters/conduit@dc50197`](https://github.com/timokoesters/conduit/commit/dc50197) (2023-06)

## What changed vs step 664

| Rust change | C++ translation |
|---|---|
| Update example configurations in DEPLOY.md for Apache and Nginx which include upstream proxy timeouts of 5 minutes to allow for room joins which take a while. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
