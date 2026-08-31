# Step 175 — "improvement: respect logout_devices param on password change" (Conduit `ebb38cd`)

Source: [`timokoesters/conduit@ebb38cd`](https://github.com/timokoesters/conduit/commit/ebb38cd) (2021-01)

## What changed vs step 174

| Rust change | C++ translation |
|---|---|
| Improvement: respect `logout_devices` param on password change. When user changes password, optionally log out all other devices. | **Translated** — Our `/account/password` (step 12 `b51771a_password_change`) doesn't have this param yet. Would add `logout_devices` boolean. |

## Implementation details

- Our `/account/password` (step 12 `b51771a_password_change`) doesn't have this param yet. Would add `logout_devices` boolean.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
