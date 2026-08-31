# Step 479 — "Fix security issue." (Conduit `5c6c6f2`)

Source: [`timokoesters/conduit@5c6c6f2`](https://github.com/timokoesters/conduit/commit/5c6c6f2) (2022-02)

## What changed vs step 478

| Rust change | C++ translation |
|---|---|
| Fix security issue. Security vulnerability fix. 1 file changed. | **Translated** — Security fix — applied to our equivalent code path. |

## Implementation details

- Security fix — applied to our equivalent code path.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
