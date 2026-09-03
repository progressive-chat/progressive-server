# Step 364: c3924b56 - feat: if txn id exists in the db, skip the event

**Conduit commit:** `c3924b56`
**Category:** Bug fix

## Summary

feat: if txn id exists in the db, skip the event

## C++ Translation

This commit prevents duplicate event processing by checking if the transaction ID already exists. This is a deduplication improvement that could be translated to our C++ implementation.

**Status:** Placeholder step for chronological correspondence.
