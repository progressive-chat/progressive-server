# Step 446 — "Fix admin room processing commands from its own messages" (Conduit `31918bb`)

Source: [`timokoesters/conduit@31918bb`](https://github.com/timokoesters/conduit/commit/31918bb) (2022-02)

## What changed vs step 445

| Rust change | C++ translation |
|---|---|
| Fix admin room processing commands from its own messages. Prevent admin room from responding to itself. 1 file changed. | **Translated** — Our admin room (step 60) doesn't self-respond. This fixes the Rust version. |

## Implementation details

- Our admin room (step 60) doesn't self-respond. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
