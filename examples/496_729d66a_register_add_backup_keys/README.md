# Step 496 — "feat: register missing add_backup_keys route" (Conduit `729d66a`)

Source: [`timokoesters/conduit@729d66a`](https://github.com/timokoesters/conduit/commit/729d66a) (2022-04)

## What changed vs step 495

| Rust change | C++ translation |
|---|---|
| Feat: register missing add_backup_keys route. Key backup API endpoint. 1 file changed. | **Translated** — We don't have key backup yet (step 27 started). This adds the add_backup_keys route. |

## Implementation details

- We don't have key backup yet (step 27 started). This adds the add_backup_keys route.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
