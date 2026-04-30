import { Logger } from '@nestjs/common';

const logger = new Logger('QueryOptimization');

/**
 * Query Optimization Utilities
 * 
 * These utilities help prevent N+1 query problems and improve database performance.
 * 
 * N+1 Query Problem:
 * - BAD: Fetching a list, then running a query for each item
 * - GOOD: Fetching all data in one or two queries using JOINs or IN clauses
 * 
 * Examples of N+1 patterns to avoid:
 * 
 * BAD (N+1):
 * ```
 * const risks = await prisma.risk.findMany();
 * for (const risk of risks) {
 *   const owner = await prisma.user.findUnique({ where: { id: risk.ownerId } });
 * }
 * ```
 * 
 * GOOD (with include):
 * ```
 * const risks = await prisma.risk.findMany({
 *   include: { owner: { select: { id: true, displayName: true } } }
 * });
 * ```
 * 
 * GOOD (batch fetch):
 * ```
 * const risks = await prisma.risk.findMany();
 * const ownerIds = [...new Set(risks.map(r => r.ownerId).filter(Boolean))];
 * const owners = await prisma.user.findMany({ where: { id: { in: ownerIds } } });
 * const ownerMap = new Map(owners.map(o => [o.id, o]));
 * ```
 */

/**
 * Batch loader for preventing N+1 queries when fetching related entities.
 * 
 * Usage:
 * ```
 * const loader = createBatchLoader(
 *   async (ids) => prisma.user.findMany({ where: { id: { in: ids } } }),
 *   (user) => user.id
 * );
 * 
 * // Later, load users for each risk
 * const users = await loader.loadMany(risks.map(r => r.ownerId).filter(Boolean));
 * ```
 */
export function createBatchLoader<T, K extends string | number>(
  batchFn: (keys: K[]) => Promise<T[]>,
  keyFn: (item: T) => K,
) {
  const cache = new Map<K, T>();
  const pending = new Map<K, Promise<T | null>>();

  return {
    /**
     * Load a single item by key
     */
    async load(key: K): Promise<T | null> {
      if (cache.has(key)) {
        return cache.get(key)!;
      }

      if (pending.has(key)) {
        return pending.get(key)!;
      }

      const promise = batchFn([key]).then((items) => {
        const item = items[0] || null;
        if (item) cache.set(key, item);
        pending.delete(key);
        return item;
      });

      pending.set(key, promise);
      return promise;
    },

    /**
     * Load multiple items by keys (batched into single query)
     */
    async loadMany(keys: K[]): Promise<Map<K, T>> {
      const uniqueKeys = [...new Set(keys)];
      const uncachedKeys = uniqueKeys.filter((k) => !cache.has(k));

      if (uncachedKeys.length > 0) {
        const items = await batchFn(uncachedKeys);
        for (const item of items) {
          cache.set(keyFn(item), item);
        }
      }

      const result = new Map<K, T>();
      for (const key of keys) {
        const item = cache.get(key);
        if (item) result.set(key, item);
      }
      return result;
    },

    /**
     * Clear the cache
     */
    clear(): void {
      cache.clear();
      pending.clear();
    },
  };
}

/**
 * Chunk an array into smaller batches for processing
 * Useful when you need to process large arrays in batches to avoid
 * overwhelming the database or hitting query limits.
 */
export function chunkArray<T>(array: T[], chunkSize: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    chunks.push(array.slice(i, i + chunkSize));
  }
  return chunks;
}

/**
 * Process items in parallel with concurrency limit
 * Prevents overwhelming the database with too many concurrent queries
 */
export async function parallelProcess<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  concurrency = 10,
): Promise<R[]> {
  const results: R[] = [];
  const chunks = chunkArray(items, concurrency);

  for (const chunk of chunks) {
    const chunkResults = await Promise.all(chunk.map(processor));
    results.push(...chunkResults);
  }

  return results;
}

/**
 * Process items in batches (useful for bulk database operations)
 */
export async function batchProcess<T, R>(
  items: T[],
  batchProcessor: (batch: T[]) => Promise<R>,
  batchSize = 100,
): Promise<R[]> {
  const batches = chunkArray(items, batchSize);
  const results: R[] = [];

  for (const batch of batches) {
    const result = await batchProcessor(batch);
    results.push(result);
  }

  return results;
}

/**
 * Decorator to warn about potential N+1 queries in development
 */
export function WarnN1Query(threshold = 5) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const queryCountBefore = (this as any).prisma?.queryCount || 0;
      const result = await originalMethod.apply(this, args);
      const queryCountAfter = (this as any).prisma?.queryCount || 0;
      const queriesExecuted = queryCountAfter - queryCountBefore;

      if (
        queriesExecuted > threshold &&
        process.env.NODE_ENV === 'development'
      ) {
        logger.warn(
          `Potential N+1 detected in ${target.constructor.name}.${propertyKey}: ` +
            `${queriesExecuted} queries executed (threshold: ${threshold})`,
        );
      }

      return result;
    };

    return descriptor;
  };
}

/**
 * Helper to extract unique IDs from an array of objects
 */
export function extractUniqueIds<T>(
  items: T[],
  idFn: (item: T) => string | null | undefined,
): string[] {
  return [...new Set(items.map(idFn).filter((id): id is string => !!id))];
}

/**
 * Create a lookup map from an array of objects
 */
export function createLookupMap<T>(
  items: T[],
  keyFn: (item: T) => string,
): Map<string, T> {
  return new Map(items.map((item) => [keyFn(item), item]));
}

/**
 * Optimized query patterns documentation
 * 
 * 1. Use `include` or `select` with nested relations:
 *    ```
 *    prisma.risk.findMany({
 *      include: {
 *        owner: { select: { id: true, displayName: true } },
 *        controls: { select: { id: true, title: true } },
 *      }
 *    })
 *    ```
 * 
 * 2. Use `groupBy` for aggregations:
 *    ```
 *    prisma.risk.groupBy({
 *      by: ['status'],
 *      where: { organizationId },
 *      _count: true,
 *    })
 *    ```
 * 
 * 3. Use `count` for totals:
 *    ```
 *    prisma.risk.count({ where: { organizationId } })
 *    ```
 * 
 * 4. Use `findMany` with `in` for batch fetches:
 *    ```
 *    prisma.user.findMany({
 *      where: { id: { in: ownerIds } }
 *    })
 *    ```
 * 
 * 5. Use transactions for related writes:
 *    ```
 *    prisma.$transaction([
 *      prisma.risk.update(...),
 *      prisma.auditLog.create(...),
 *    ])
 *    ```
 */

