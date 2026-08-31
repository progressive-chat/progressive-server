# Step 475 — "Add show-config admin room command" (Conduit `196c839`)

Source: [`timokoesters/conduit@196c839`](https://github.com/timokoesters/conduit/commit/196c839) (2022-02)

## What changed vs step 474

| Rust change | C++ translation |
|---|---|
| Add show-config admin room command. Admin command to display current configuration. 3 files changed. | **Translated** — Our admin commands (step 60) don't have show-config. This adds the command. |

## Implementation details

- Our admin commands (step 60) don't have show-config. This adds the command.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
