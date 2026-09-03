# Step 255 — "Create admin room and hide migration messages on first run" (Conduit `e1c0dcb`)

Source: [`timokoesters/conduit@e1c0dcb`](https://github.com/timokoesters/conduit/commit/e1c0dcb) (2022-02-03)

## What changed vs step 254

| Rust change | C++ translation |
|---|---|
| **Admin room first run** | **Translated** — Admin room first run |
| **Major admin refactor** | **Translated** — Cleaner admin code |
| **Major account refactor** | **Translated** — Cleaner account code |

## Implementation details

1. **Admin room first run** — Create admin room and hide migration messages on first run
2. **Major admin refactor** — Major refactor of admin code
3. **Major account refactor** — Major refactor of account code

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
