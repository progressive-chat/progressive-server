# Step 69 — "fix: make element not show "unknown user" warning" (Conduit `515465f`)

Source: [`timokoesters/conduit@515465f`](https://github.com/timokoesters/conduit/commit/515465f) (2020-08)

## What changed vs step 68

| Rust change | C++ translation |
|---|---|
| Fix: `GET /profile/{userId}` returns `M_NOT_FOUND` (404) when the user does not exist, instead of a generic error. | **Translated** — our step 28 (`515465f9_profile_404`) implements this fix. |

## Implementation details

- **Translated** — our step 28 (`515465f9_profile_404`) implements this fix.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
