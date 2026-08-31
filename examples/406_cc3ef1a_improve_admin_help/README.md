# Step 406 — "Improve help text for admin commands" (Conduit `cc3ef1a`)

Source: [`timokoesters/conduit@cc3ef1a`](https://github.com/timokoesters/conduit/commit/cc3ef1a) (2022-01)

## What changed vs step 405

| Rust change | C++ translation |
|---|---|
| Improve help text for admin commands. Better CLI help for admin commands. | **Translated** — Our admin commands (step 60) have help. This improves the text. |

## Implementation details

- Our admin commands (step 60) have help. This improves the text.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
