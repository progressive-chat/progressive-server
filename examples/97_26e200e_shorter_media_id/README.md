# Step 97 — "Reduce media ID length from 256 to 32" (Conduit `26e200e`)

Source: [`timokoesters/conduit@26e200e`](https://github.com/timokoesters/conduit/commit/26e200e) (2020-09)

## What changed vs step 96

| Rust change | C++ translation |
|---|---|
| Reduces the media ID length from 256 to 32 characters. | **Partially implemented** — Validation not added |

## Implementation details

The Conduit commit reduces `MXC_LENGTH` from 256 to 32 characters. In our C++ implementation:

1. **No fixed length constant** — Our `Media::create()` accepts the mxc string as-is without length validation
2. **Validation not added** — We could add a check to enforce max 32 chars but haven't yet

**Status:** Partially implemented — core media storage works, but length validation not added

## Implementation details (if we were to add it)

```cpp
// In media.cpp create() method:
constexpr size_t MXC_LENGTH = 32;
if (mxc.size() > MXC_LENGTH) {
    throw std::runtime_error("MXC URI too long");
}
```

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
