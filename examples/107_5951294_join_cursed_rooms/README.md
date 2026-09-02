# Step 107 — "feat: join cursed rooms" (Conduit `5951294`)

Source: [`timokoesters/conduit@5951294`](https://github.com/timokoesters/conduit/commit/5951294) (2021-04-14)

## What changed vs step 106

| Rust change | C++ translation |
|---|---|
| **Join cursed rooms** | **Translated** — Join cursed rooms |
| **Better error handling** | **Translated** — Continue on auth failures |

## Implementation details

1. **Join cursed rooms** — Remove several restrictions and try to continue verifying PDU events if some auth events fail (drops/ignores bad PDUs)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
