/**
 * Tests for the Phase 2 rate limiter (`src/server/tenant/rateLimit.ts`).
 *
 * Proves: burst over RPM is blocked with retryAfter, dimensions are
 * isolated per tenant (one tenant's burst never blocks another),
 * concurrency caps hold, and the Redis stub stays env-gated.
 */
import test from "node:test";
import assert from "node:assert/strict";

const { InMemoryRateLimiter, RedisRateLimiter } =
  await import("../../../src/server/tenant/rateLimit.ts");

const ctx = (over: Record<string, string> = {}) => ({
  tenantId: "t1",
  apiKeyId: "k1",
  ip: "10.0.0.1",
  ...over,
});

test("allows under RPM, blocks burst with retryAfterMs", async () => {
  const rl = new InMemoryRateLimiter();
  for (let i = 0; i < 5; i++) {
    assert.equal((await rl.check(ctx(), { rpm: 5 })).allowed, true);
  }
  const blocked = await rl.check(ctx(), { rpm: 5 });
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.deniedBy, "key");
  assert.ok((blocked.retryAfterMs ?? 0) > 0);
});

test("per-tenant isolation: t2 unaffected by t1 burst", async () => {
  const rl = new InMemoryRateLimiter();
  for (let i = 0; i < 3; i++) await rl.check(ctx(), { rpm: 3 });
  assert.equal((await rl.check(ctx(), { rpm: 3 })).allowed, false);
  // NOTE: distinct IP so the shared per-IP bucket does not trip — this test
  // proves tenant/key buckets are isolated; per-IP global blocking is covered below.
  const other = await rl.check(ctx({ tenantId: "t2", apiKeyId: "k2", ip: "10.0.0.2" }), { rpm: 3 });
  assert.equal(other.allowed, true);
});

test("per-IP bucket blocks shared-IP bursts independently", async () => {
  const rl = new InMemoryRateLimiter();
  for (let i = 0; i < 2; i++) {
    await rl.check(ctx({ tenantId: `t${i}`, apiKeyId: `k${i}` }), { rpm: 100 });
  }
  const blocked = await rl.check(ctx({ tenantId: "tx", apiKeyId: "kx" }), { rpm: 2 });
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.deniedBy, "ip");
});

test("tpm and concurrency caps are enforced", async () => {
  const rl = new InMemoryRateLimiter();
  assert.equal((await rl.check(ctx(), { rpm: 100, tpm: 10 }, { tokens: 6 })).allowed, true);
  assert.equal((await rl.check(ctx(), { rpm: 100, tpm: 10 }, { tokens: 5 })).allowed, false);
  const rc = new InMemoryRateLimiter();
  assert.equal((await rc.check(ctx(), { rpm: 100, concurrency: 1 })).allowed, true);
  assert.equal((await rc.check(ctx(), { rpm: 100, concurrency: 1 })).deniedBy, "concurrency");
  rc.release("k1");
  assert.equal((await rc.check(ctx(), { rpm: 100, concurrency: 1 })).allowed, true);
});

test("RedisRateLimiter throws NOT_CONFIGURED without backend", async () => {
  const stub = new RedisRateLimiter();
  assert.equal(stub.configured, process.env.REDIS_URL != null);
  await assert.rejects(() => stub.check(ctx(), { rpm: 1 }), /NOT_CONFIGURED/);
});

test("Zod rejects invalid context/limits", async () => {
  const rl = new InMemoryRateLimiter();
  await assert.rejects(() => rl.check(ctx({ tenantId: "" }), { rpm: 1 }));
  await assert.rejects(() => rl.check(ctx(), { rpm: 0 }));
});
