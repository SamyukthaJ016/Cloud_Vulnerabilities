# infra/queue/

BullMQ bootstrap. Registers queues used across the app. Workers (queue consumers) live in their owning feature module.

## Queues

| Name | Producer | Consumer | Purpose |
|---|---|---|---|
| `webhook-delivery` | `webhooks-outbound` service | `webhooks-outbound` delivery worker | Flow Q1 — deliver customer webhook with retries |

> Scan dispatch is **synchronous** in v1 (direct HTTP call from `scans` →
> external scanner). No queue involved. See `modules/scans/README.md`.

## Rules

- **Queue name constants live in `queues.constants.ts`.** Never hardcode a queue name string in a producer/consumer.
- **Producers:** inject `@InjectQueue(QUEUE_NAMES.X)` and call `.add(jobName, data, opts)`.
- **Consumers:** use `@Processor(QUEUE_NAMES.X)` on a class, inside the owning module.
- **Job payloads must be JSON-serializable.** Don't put Prisma client objects in job data — pass IDs and re-fetch.
- **Idempotency:** jobs may be retried — every worker must handle being called twice for the same payload.
