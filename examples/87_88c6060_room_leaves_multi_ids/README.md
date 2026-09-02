# Step 87 — "Add ability to update room leaves with multiple eventIds" (Conduit `88c6060`)

Source: [`timokoesters/conduit@88c6060`](https://github.com/timokoesters/conduit/commit/88c6060) (2021-02-23)

## What changed vs step 86

| Rust change | C++ translation |
|---|---|
| **Update room leaves with multiple eventIds** | **Translated** — Multi-id room leaves |

## Implementation details

1. **Room leaves multi-id** — Add ability to update room leaves with multiple eventIds
2. **Database rooms refactor** — Cleaner room leaves handling

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
