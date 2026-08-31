# Step 130 — "improvement: more logging" (Conduit `6e36081`)

Source: [`timokoesters/conduit@6e36081`](https://github.com/timokoesters/conduit/commit/6e36081) (2020-12)

## What changed vs step 129

| Rust change | C++ translation |
|---|---|
| More logging: log the type of every incoming event, log when an appservice is registered, etc. | **Translated** — Our step 6 onwards has logging in all main paths. The specific appservice logging comes in step 96 (`98e2bed`). |

## Implementation details

- Our step 6 onwards has logging in all main paths. The specific appservice logging comes in step 96 (`98e2bed`).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
