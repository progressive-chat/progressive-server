# Step 673 — "fix: never try federation with self" (Conduit `c171877`)

Source: [`timokoesters/conduit@c171877`](https://github.com/timokoesters/conduit/commit/c171877) (2023-07)

## What changed vs step 672

| Rust change | C++ translation |
|---|---|
| Fix: never try federation with self. Prevent self-federation attempts. | **Already implemented** — Our `federation_send_to_remotes` (line 92) skips servers matching our hostname. |

## Implementation details

- **main.cpp (federation_send_to_remotes)**: Already contains `if (srv == ctx->data->hostname()) continue;` to skip self-federation.

This fix was already present in our federation implementation from earlier steps.

**Status:** Already implemented (no changes needed).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```