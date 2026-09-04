# Step 90 — "fix: don't always query aliases of appservices" (Conduit `f2ec2be`)

Source: [`timokoesters/conduit@f2ec2be`](https://github.com/timokoesters/conduit/commit/f2ec2be) (2021-03-03)

## What changed vs step 89

| Rust change | C++ translation |
|---|---|
| **Don't always query aliases of appservices** | **Translated** — Only query appservice aliases matching regex |

## Implementation details

1. **Added regex header** in main.cpp for alias pattern matching
2. **Updated get_alias_route** to check appservice alias regex before querying:
   - Iterates through all registered appservices
   - For each appservice, checks if the room alias matches any of its alias namespace regex patterns
   - Only queries appservices whose alias regex matches the room alias
3. **Added get_all_appservices() method** to AppserviceManager:
   - Returns const reference to the appservices map
   - Thread-safe with mutex locking

**Status:** Real implementation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```