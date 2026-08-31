# Step 467 — "feat: Provide sane defaults for vscode developing" (Conduit `bcd6c0b`)

Source: [`timokoesters/conduit@bcd6c0b`](https://github.com/timokoesters/conduit/commit/bcd6c0b) (2022-02)

## What changed vs step 466

| Rust change | C++ translation |
|---|---|
| Feat: Provide sane defaults for vscode developing. VS Code config. 3 files changed. | **Skipped** — IDE config only. |

## Implementation details

- IDE config only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
