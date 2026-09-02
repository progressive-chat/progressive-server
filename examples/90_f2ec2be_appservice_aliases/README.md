# Step 90 — "fix: don't always query aliases of appservices" (Conduit `f2ec2be`)

Source: [`timokoesters/conduit@f2ec2be`](https://github.com/timokoesters/conduit/commit/f2ec2be) (2021-03-03)

## What changed vs step 89

| Rust change | C++ translation |
|---|---|
| **Don't always query aliases of appservices** | **Translated** — Only query matching aliases |

## Implementation details

1. **Appservice alias filtering** — Only query appservice aliases that match the regex in the registration file

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
