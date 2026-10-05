/**
 * Multitenant rate limiter (Phase 2 shim).
 *
 * Multi-dimensional sliding-window limiter: every request is checked against
 * per-key + per-tenant + per-IP buckets (request count, optional token sum,
 * optional concurrency). In-memory only — no DB writes on the hot path.
 *
 * IMPORTANT: usage accounting MUST stay async/fire-and-forget. Never block
 * the streaming hot path (`open-sse/handlers/chatCore.ts`) with DB writes;
 * persist `usage_events` from a background flush (see docs/multitenant/).
 */
import { z } from "zod";

export const rateLimitContextSchema = z.object({
  tenantId: z.string().min(1).max(128),
  apiKeyId: z.string().min(1).max(128),
  ip: z.string().min(1).max(64),
});

export const rateLimitsSchema = z.object({
  rpm: z.number().int().positive().max(100000),
  tpm: z.number().int().positive().max(100000000).optional(),
  concurrency: z.number().int().positive().max(10000).optional(),
});

export type RateLimitContext = z.infer<typeof rateLimitContextSchema>;
export type RateLimits = z.infer<typeof rateLimitsSchema>;

export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs?: number;
  /** Which dimension denied: "key" | "tenant" | "ip" | "concurrency". */
  deniedBy?: "key" | "tenant" | "ip" | "concurrency";
  remaining?: number;
}

export interface RateLimiter {
  check(
    ctx: RateLimitContext,
    limits: RateLimits,
    opts?: { tokens?: number }
  ): Promise<RateLimitResult>;
}

const WINDOW_MS = 60_000;

interface Hit {
  at: number;
  tokens: number;
}

/** Sliding-window in-memory limiter. Single-process; use Redis for N replicas. */
export class InMemoryRateLimiter implements RateLimiter {
  private windows = new Map<string, Hit[]>();
  private inFlight = new Map<string, number>();

  async check(
    ctx: RateLimitContext,
    limits: RateLimits,
    opts?: { tokens?: number }
  ): Promise<RateLimitResult> {
    rateLimitContextSchema.parse(ctx);
    rateLimitsSchema.parse(limits);
    const tokens = opts?.tokens ?? 0;
    const now = Date.now();
    const dims = [
      { name: "key" as const, bucket: `key:${ctx.apiKeyId}` },
      { name: "tenant" as const, bucket: `tenant:${ctx.tenantId}` },
      { name: "ip" as const, bucket: `ip:${ctx.ip}` },
    ];
    for (const { name, bucket } of dims) {
      const hits = this.prune(bucket, now);
      if (hits.length >= limits.rpm) {
        return { allowed: false, deniedBy: name, retryAfterMs: hits[0].at + WINDOW_MS - now };
      }
      if (limits.tpm !== undefined) {
        const used = hits.reduce((sum, h) => sum + h.tokens, 0);
        if (used + tokens > limits.tpm) {
          return { allowed: false, deniedBy: name, retryAfterMs: hits[0].at + WINDOW_MS - now };
        }
      }
    }
    if (limits.concurrency !== undefined) {
      const active = this.inFlight.get(`key:${ctx.apiKeyId}`) ?? 0;
      if (active >= limits.concurrency) {
        return { allowed: false, deniedBy: "concurrency", retryAfterMs: 1000 };
      }
      this.inFlight.set(`key:${ctx.apiKeyId}`, active + 1);
    }
    for (const { bucket } of dims) {
      this.windows.get(bucket)?.push({ at: now, tokens });
    }
    const keyHits = this.windows.get(`key:${ctx.apiKeyId}`) ?? [];
    return { allowed: true, remaining: Math.max(0, limits.rpm - keyHits.length) };
  }

  /** Release one concurrency slot acquired by {@link check}. */
  release(apiKeyId: string): void {
    const active = this.inFlight.get(`key:${apiKeyId}`) ?? 0;
    if (active <= 1) this.inFlight.delete(`key:${apiKeyId}`);
    else this.inFlight.set(`key:${apiKeyId}`, active - 1);
  }

  /** Test/ops helper: drop all buckets. */
  reset(): void {
    this.windows.clear();
    this.inFlight.clear();
  }

  private prune(bucket: string, now: number): Hit[] {
    const cutoff = now - WINDOW_MS;
    const kept = (this.windows.get(bucket) ?? []).filter((h) => h.at > cutoff);
    this.windows.set(bucket, kept);
    return kept;
  }
}

export const NOT_CONFIGURED = "NOT_CONFIGURED";

/**
 * Redis-backed limiter stub (Phase 2). Same interface, no `redis` dependency.
 * Set `REDIS_URL` (e.g. `redis://redis:6379`) when the shared Redis lands;
 * until then every call throws NOT_CONFIGURED so callers fall back to memory.
 */
export class RedisRateLimiter implements RateLimiter {
  private readonly redisUrl: string | null;

  constructor(redisUrl?: string) {
    this.redisUrl = redisUrl ?? process.env.REDIS_URL ?? null;
  }

  get configured(): boolean {
    return this.redisUrl !== null;
  }

  async check(): Promise<RateLimitResult> {
    throw new Error(
      `${NOT_CONFIGURED}: RedisRateLimiter has no backend yet. ` +
        (this.redisUrl ? "Backend not implemented — use InMemoryRateLimiter." : "Set REDIS_URL.")
    );
  }
}
