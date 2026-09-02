# Step 78 — "Fix and integrate outlier tree, build forks after adding event to DB" (Conduit `56b816a`)

Source: [`timokoesters/conduit@56b816a`](https://github.com/timokoesters/conduit/commit/56b816a) (2021-01-29)

## What changed vs step 77

| Rust change | C++ translation |
|---|---|
| **Fix and integrate outlier tree** | **Translated** — Outlier tree fixes |
| **Build forks after adding event to DB** | **Translated** — Forks after event add |

## Implementation details

1. **Outlier tree fixes** — Fix and integrate the outlier events tree
2. **Forks after event** — Build forks after adding event to DB
3. **Major server_server refactor** — Significant refactor

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
