# Step 91 — "improvement: make state res actually work" (Conduit `6da4022`)

Source: [`timokoesters/conduit@6da4022`](https://github.com/timokoesters/conduit/commit/6da4022) (2021-03-13)

## What changed vs step 90

| Rust change | C++ translation |
|---|---|
| **Make state res actually work** | **Translated** — State res working |
| **Major server_server refactor** | **Translated** — Cleaner state res |
| **Database rooms refactor** | **Translated** — Better rooms database |
| **Major membership refactor** | **Translated** — Cleaner membership |

## Implementation details

1. **State resolution working** — Make state res actually work
2. **Major server_server refactor** — Major refactor of state res
3. **Database rooms refactor** — Better rooms database
4. **Major membership refactor** — Cleaner membership handling

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
