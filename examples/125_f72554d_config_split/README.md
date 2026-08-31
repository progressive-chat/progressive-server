# Step 125 — "Split config into a Debian and local part" (Conduit `f72554d`)

Source: [`timokoesters/conduit@f72554d`](https://github.com/timokoesters/conduit/commit/f72554d) (2020-11)

## What changed vs step 124

| Rust change | C++ translation |
|---|---|
| Splits the config into a Debian part (system-wide) and a local part (user overrides). | **No-op for us** — We use env-var-only config (step 99 in the date tail). No config file yet. |

## Implementation details

- We use env-var-only config (step 99 in the date tail). No config file yet.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
