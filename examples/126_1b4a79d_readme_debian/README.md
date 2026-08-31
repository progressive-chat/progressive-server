# Step 126 — "Add and install README.Debian" (Conduit `1b4a79d`)

Source: [`timokoesters/conduit@1b4a79d`](https://github.com/timokoesters/conduit/commit/1b4a79d) (2020-11)

## What changed vs step 125

| Rust change | C++ translation |
|---|---|
| Adds README.Debian for the Debian package. | **Skipped** — Debian-specific documentation. |

## Implementation details

- Debian-specific documentation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
