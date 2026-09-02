# Step 140 — "fix: deactivate accounts that should be deactivated" (Conduit `88cf043`)

Source: [`timokoesters/conduit@88cf043`](https://github.com/timokoesters/conduit/commit/88cf043) (2021-05-30)

## What changed vs step 139

| Rust change | C++ translation |
|---|---|
| **Deactivate accounts that should be** | **Translated** — Account deactivation fix |
| **Major media refactor** | **Translated** — Cleaner media code |

## Implementation details

1. **Account deactivation fix** — Deactivate accounts that should be deactivated
2. **Major media refactor** — Major refactor of media database

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
