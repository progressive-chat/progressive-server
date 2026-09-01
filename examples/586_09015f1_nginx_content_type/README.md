# Step 586 — "Describe a better way to enforce Content-Type in nginx" (Conduit `09015f1`)

Source: [`timokoesters/conduit@09015f1`](https://github.com/timokoesters/conduit/commit/09015f1) (2022-11)

## What changed vs step 585

| Rust change | C++ translation |
|---|---|
| Describe a better way to enforce Content-Type in nginx. Documentation. | **Skipped** — Nginx config documentation only. |

## Implementation details

- Nginx config documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
