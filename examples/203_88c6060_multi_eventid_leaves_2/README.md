# Step 203 — "Add ability to update room leaves with multiple eventIds" (Conduit `88c6060`)

Source: [`timokoesters/conduit@88c6060`](https://github.com/timokoesters/conduit/commit/88c6060) (2021-02)

## What changed vs step 202

| Rust change | C++ translation |
|---|---|
| Add ability to update room leaves with multiple event IDs. Duplicate of step 179 (3a6f264). | **Translated** — Our `pdu_leaves_replace` already accepts multiple leaves. |

## Implementation details

- Our `pdu_leaves_replace` already accepts multiple leaves.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
