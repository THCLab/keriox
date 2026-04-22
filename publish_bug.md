# Bug report: `publish` / `notify_witnesses` swallow witness send failures

**Project:** `keri-controller` (Rust)  
**Area:** witness notification — `Communication::publish`, `Identifier::notify_witnesses`  
**Severity:** High for correctness; witness rejection or transport errors are invisible to callers.

---

## 1) What it does now

### `Communication::publish`

In `src/communication.rs`, `publish` sends one or more messages to each witness via `send_message_to`, using `futures::future::join_all(...).await`, then **always returns `Ok(())`** without inspecting the `Result` of each future.

So any failure from `send_message_to` (HTTP error, witness refusing the event, wrong endpoint, etc.) is **discarded**.

### `Identifier::notify_witnesses`

In `src/identifier/mechanics/notify_witness.rs`, `notify_witnesses` builds futures that call `self.communication.publish(...)`, runs `join_all(to_notify).await`, then **`self.to_notify.clear()`** unconditionally.

Again, **no check** that each `publish` (and thus each underlying send) succeeded.

### Observable consequence

Callers that follow the documented pattern (`finalize_*` → `notify_witnesses`) can observe:

- Local KEL / identifier state updated as if the key event were fully processed.
- **No error** when the witness never accepted the event (e.g. duplicate `sn` / fork rejected under first-seen rules, or network failure).

Downstream code cannot distinguish “witness has this event” from “we only think we told the witness.”

---

## 2) Why this is a problem downstream

1. **Silent divergence**  
   Controllers that assume “after `notify_witnesses` returns Ok, witnesses have been updated” are wrong. Local state and witness KEL can diverge with no signal.

2. **Fork / equivocation scenarios**  
   If a client replays from an older DB snapshot and produces a conflicting rotation at the same `sn`, a witness may reject the second branch. The client still completes `finalize_rotate` and `notify_witnesses` successfully; only later steps (or manual witness query) reveal the witness never moved.

3. **False confidence in tests and demos**  
   Integration tests that only assert local `find_state` after rotation pass even when the witness rejected the event, unless they independently query the witness.

4. **Forces fragile workarounds**  
   Consumers must re-implement checks (e.g. partially-witnessed escrow, independent witness KEL query, or wrapping HTTP) to detect failures that the API surface suggests should already be reflected in `Result`.

---

## 3) How to reproduce (and turn into a unit test)

### Idea

Use a **transport mock** that returns `Err` from the send path used by `publish` (the same path `send_message_to` uses for witness HTTP delivery). After `finalize_rotate` (or `finalize_incept` with witnesses) and `notify_witnesses().await`, assert that:

- Either **`notify_witnesses` returns `Err`**, or  
- **`publish` returns `Err`** (depending on where you choose to surface the error),

and optionally assert that **`to_notify` is not cleared** on failure so the client can retry.

Today, with a failing transport, **`notify_witnesses` still returns `Ok`** and **`to_notify` is cleared**, so the test expectation is the opposite of current behavior — that is the bug.

### Concrete steps (integration-style)

1. Construct a `Controller` / `Identifier` with a **test `Transport` implementation** whose `send_message` (or equivalent used by witness publish) returns `Err(...)` for witness-directed messages (or for all messages after the first success, to simulate intermittent failure).

2. Complete a normal witnessed inception and first rotation so the code path uses `publish` with real witness prefixes (or minimal fixture data matching your test harness).

3. Configure the mock to **fail on the next** `send_message_to` / publish batch (e.g. second rotation, or first rotation after incept).

4. Call `identifier.notify_witnesses().await`.

**Expected (correct):** `Err` propagates; caller knows the witness was not updated.  
**Actual (bug):** `Ok`; queue cleared; local state may already reflect the event.

### Unit test shape (pseudo-Rust)

```rust
// Pseudocode — names depend on your Transport trait and test helpers.

#[tokio::test]
async fn notify_witnesses_propagates_publish_errors() {
    let transport = Arc::new(FailingTransport::new(/* fail on witness send */));
    let controller = Controller::new_with_transport(/* db + transport */).unwrap();
    // ... incept + finalize, or load fixture ...

    let mut id = /* identifier */;

    let err = id.notify_witnesses().await;
    assert!(err.is_err(), "notify_witnesses must not succeed when publish fails");

    // Optional: ensure to_notify was not dropped so callers can retry
    // assert!(!id.to_notify.is_empty());
}
```

If the test harness cannot inject a custom transport easily, an alternative is a **local TCP server** that accepts connections then resets / closes, and point the witness URL at it — less ideal for CI but still proves “network failure → today still Ok”.

---

## 4) Suggestions for how to fix it

### Minimal fix (recommended first step)

1. **`Communication::publish`**  
   - Collect `Vec<Result<_, _>>` from `join_all`.  
   - If any entry is `Err`, return that error (or aggregate with `?` in a loop).  
   - Only return `Ok(())` if every send succeeded.

2. **`Identifier::notify_witnesses`**  
   - Await each `publish` future and **propagate `Err`**.  
   - **Do not call `to_notify.clear()`** unless all publishes succeeded (or split into “take batch, attempt publish, on failure re-push or leave queue” — simplest is clear only on full success).

This restores the usual Rust contract: **`Result` means the operation the name describes actually completed**.

### Follow-ups (optional)

- **Logging:** On partial failure in multi-witness sends, log which witness index failed before returning `Err`.

- **API clarity:** Consider returning structured errors (which witness, which message) for operators.

- **Semantics doc:** Document whether `notify_witnesses` is “best effort” vs “all witnesses acknowledged”; today it reads as the latter but behaves like the former.

### Non-goals / careful design

- Some deployments may want “fire and forget.” If so, expose that as **`notify_witnesses_best_effort()`** or a feature flag, rather than making the default silent failure.

---

## References (for maintainers tracing the code)

- `keri-controller/src/communication.rs` — `publish`: `join_all(...).await` then unconditional `Ok(())`.  
- `keri-controller/src/identifier/mechanics/notify_witness.rs` — `notify_witnesses`: `join_all(...).await` then `to_notify.clear()` with no error handling.

---

## Summary one-liner for issue title

**Witness `publish` / `notify_witnesses` discards `Result` from `send_message_to`, causing silent divergence when witness rejects or network fails.**
