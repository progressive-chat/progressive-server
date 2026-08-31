# Step 219 — "fix: don't always query aliases of appservices" (Conduit `f2ec2be`)

Source: [`timokoesters/conduit@f2ec2be`](https://github.com/timokoesters/conduit/commit/f2ec2be) (2021-03)

## What changed vs step 218

| Rust change | C++ translation |
|---|---|
| Fix: don't always query aliases of appservices. Only query appservice aliases when necessary. | **Translated** — Our appservice dispatch (step 96) already checks namespace. This optimizes it. |

## Implementation details

- Our appservice dispatch (step 96) already checks namespace. This optimizes it.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
