# Step 350: 07a3a6fa - Return an error when signing an event fails Prevents the server from crashing/become unresponsive when overly long messages are sent

**Conduit commit:** `07a3a6fa`
**Category:** Bug fix

## Summary

Return an error when signing an event fails Prevents the server from crashing/become unresponsive when overly long messages are sent

## C++ Translation

This commit prevents crashes when event signing fails. This is a robustness improvement that could be translated to our C++ implementation.

**Status:** Placeholder step for chronological correspondence.
