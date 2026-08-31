# Step 139 — "Fix review issues, Remove EventHash's in prev/auth_events in StateEvent" (Conduit `234b226`)

Source: [`timokoesters/conduit@234b226`](https://github.com/timokoesters/conduit/commit/234b226) (2020-12)

## What changed vs step 138

| Rust change | C++ translation |
|---|---|
| Fix review issues, remove EventHash's in prev/auth_events in StateEvent. Uses canonical JSON values instead of strings. | **No-op for us** — Our canonical JSON conversion is done in `crypto::sign_json`. The intermediate EventHash type doesn't exist in C++. |

## Implementation details

- Our canonical JSON conversion is done in `crypto::sign_json`. The intermediate EventHash type doesn't exist in C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
