# Step 439 — "Create admin room and hide migration messages on first run" (Conduit `e1c0dcb`)

Source: [`timokoesters/conduit@e1c0dcb`](https://github.com/timokoesters/conduit/commit/e1c0dcb) (2022-02)

## What changed vs step 438

| Rust change | C++ translation |
|---|---|
| Create admin room and hide migration messages on first run. Admin room auto-creation and migration UX. 3 files changed. | **Translated** — Our admin room (step 60) is created on startup. This hides migration messages. |

## Implementation details

- Our admin room (step 60) is created on startup. This hides migration messages.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
