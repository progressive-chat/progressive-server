# Step 279: 2a00c547 - improvement: faster /syncs

**Conduit commit:** `2a00c547`
**Category:** Performance optimization

## Summary

improvement: faster /syncs

## C++ Translation

This commit adds a cache for `last_timeline_count` to speed up `/sync` requests.

### Changes:
1. **database.hpp**: Added `last_timeline_count_mutex` and `last_timeline_count_cache` (unordered_map<string, uint64_t>) to the Database class
2. **data.hpp/data.cpp**: Added `Data::last_timeline_count(room_id)` method that:
   - Checks the cache first (fast path)
   - If not cached, finds the last PDU index by iterating backwards from UINT64_MAX
   - Stores the result in cache for future calls
3. **data.cpp (pdu_append)**: Updates the cache when a new PDU is inserted
4. **main.cpp (sync_route)**: Uses the cache optimization:
   - For initial sync: returns full timeline, sets `limited` if >10 events
   - For incremental sync: checks if `last_timeline_count <= since`; if so, skips PDU fetch entirely
   - Otherwise fetches new events and takes last 10 for timeline

This mirrors Conduit's optimization where it caches the last timeline count per room to avoid iterating through PDUs when there are no new events.

**Status:** Real implementation (not a placeholder).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```