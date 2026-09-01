# Step 731 — "Move "redacts" key to "content" in redaction events in v11 rooms" (Conduit `a3b8eea`)

Source: [`timokoesters/conduit@a3b8eea`](https://github.com/timokoesters/conduit/commit/a3b8eea) (2023-12)

## What changed vs step 730

| Rust change | C++ translation |
|---|---|
| Move 'redacts' key to 'content' in redaction events in v11 rooms. Room v11 redaction format change. 1 file changed. | **Translated** — Follows step 694 (relax recovery). Room v11 redaction format. |

## Implementation details

- Follows step 694 (relax recovery). Room v11 redaction format.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
