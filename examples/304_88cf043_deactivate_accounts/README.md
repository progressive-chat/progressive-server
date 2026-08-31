# Step 304 — "fix: deactivate accounts that should be deactivated" (Conduit `88cf043`)

Source: [`timokoesters/conduit@88cf043`](https://github.com/timokoesters/conduit/commit/88cf043) (2021-05)

## What changed vs step 303

| Rust change | C++ translation |
|---|---|
| Fix: deactivate accounts that should be deactivated. Account deactivation (GDPR, admin). 5 files changed. | **Translated** — We don't have account deactivation yet. This adds the feature. |

## Implementation details

- We don't have account deactivation yet. This adds the feature.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
