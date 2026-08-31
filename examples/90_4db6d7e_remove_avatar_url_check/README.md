# Step 90 — "fix: remove avatar url checks" (Conduit `4db6d7e`)

Source: [`timokoesters/conduit@4db6d7e`](https://github.com/timokoesters/conduit/commit/4db6d7e) (2020-09)

## What changed vs step 89

| Rust change | C++ translation |
|---|---|
| Removes the avatar_url format check (was requiring `mxc://` prefix). | Our avatar handling is simpler — we don't enforce the mxc:// prefix check. |

## Implementation details

- Our avatar handling is simpler — we don't enforce the mxc:// prefix check.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
