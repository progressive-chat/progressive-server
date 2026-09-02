# Step 232 — "fix: changes to update to the last database engine trait definition" (Conduit `f9977ca`)

Source: [`timokoesters/conduit@f9977ca`](https://github.com/timokoesters/conduit/commit/f9977ca) (2022-01-15)

## What changed vs step 231

| Rust change | C++ translation |
|---|---|
| **DB trait definition update** | **Translated** — DB trait update |

## Implementation details

1. **DB trait update** — Update to the last database engine trait definition

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
