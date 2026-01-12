This vulnerability describes a situation where the output of an event depends on ordered or timed outputs. A race condition becomes a source of vulnerability when the required ordered or timed events do not occur in the correct order or at the proper time.

In web applications, this often happens when multiple users or automated requests simultaneously access or modify shared resources, such as inventory or account balances. If proper synchronisation isn’t in place, this can lead to unexpected results, such as duplicate transactions, oversold items, or unauthorised data changes.

## Types of Race Conditions
Generally, race condition attacks can be divided into three categories:
- **Time-of-Check to Time-of-Use (TOCTOU)**: A TOCTOU race condition happens when a program checks something first and uses it later, but the data changes in between. This means what was true at the time of the check might no longer be true when the action happens. It’s like checking if a toy is in stock, and by the time you click "**Buy**" someone else has already bought it. For example, two users buy the same "last item" at the same time because the stock was checked before it was updated.
- **Shared resource**: This occurs when multiple users or systems try to change the same data simultaneously without proper control. Since both updates happen together, the final result depends on which one finishes last, creating confusion. Think of two cashiers updating the same inventory spreadsheet at once, and one overwrites the other’s work.
- **Atomicity violation**: An atomic operation should happen all at once, either fully done or not at all. When parts of a process run separately, another request can sneak in between and cause inconsistent results. It’s like paying for an item, but before the system confirms it, someone else changes the price. For example, a payment is recorded, but the order confirmation fails because another request interrupts the process.

---
We can use `Send Group (parallel)` in [[Burpsuite]] Repeater to try and exploit race conditions.
1. Copy a request to repeater.
2. add the tab to a group.
3. duplicate the tab with necessary numbers. 
4.  use the Repeater toolbar `Send` dropdown menu and select `Send group in parallel (last-byte sync)`, which launches all copies at once and waits for the final byte from each response, maximising the timing overlap to trigger race conditions.
5.  click `Send group (parallel)`; this will launch all requests to the server simultaneously. The server will attempt to handle them simultaneously, which may cause a timing bug to appear.

## Mitigation
- Use **atomic database transactions** so stock deduction and order creation execute as a single, consistent operation.
- Perform a **final stock validation** right before committing the transaction to prevent overselling.
- Implement **idempotency keys** for checkout requests to ensure duplicates aren’t processed multiple times.
- Apply **rate limiting** or concurrency controls to block rapid, repeated checkout attempts from the same user or session.