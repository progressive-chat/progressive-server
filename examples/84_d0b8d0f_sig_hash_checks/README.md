# Step 84 — "Fix signature/hash checks, fetch recursive auth events" (Conduit `d0b8d0f`)

Source: [`timokoesters/conduit@d0b8d0f`](https://github.com/timokoesters/conduit/commit/d0b8d0f) (2021-02-09)

## What changed vs step 83

| Rust change | C++ translation |
|---|---|
| **Fix signature/hash checks** | **Translated** — Better signature/hash validation |
| **Fetch recursive auth events** | **Translated** — Recursive auth event fetching |

## Implementation details

1. **Signature/hash checks** — Fixed signature and hash validation
2. **Recursive auth events** — Fetch auth events recursively
3. **Major server_server refactor** — Significant refactor of state res

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
