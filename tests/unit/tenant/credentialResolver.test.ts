/**
 * Phase 1 tenant credential resolvers — isolation + single-tenant fallback.
 *
 * Runner: node --import tsx/esm --test tests/unit/tenant/credentialResolver.test.ts
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  InMemoryTenantResolver,
  LocalEnvResolver,
} from "../../../src/server/tenant/credentialResolver.ts";
import type { TenantContext } from "../../../src/server/tenant/types.ts";

function ctx(tenantId: string): TenantContext {
  return { tenantId, userId: null, apiKeyId: null, plan: "default", storageMode: "LOCAL" };
}

test("tenant A never receives tenant B credentials", async () => {
  const resolver = new InMemoryTenantResolver();
  resolver.seed("tenant-a", "openai", { headers: { Authorization: "Bearer key-A" } });
  resolver.seed("tenant-b", "openai", { headers: { Authorization: "Bearer key-B" } });

  const a = await resolver.getCredential(ctx("tenant-a"), "openai");
  const b = await resolver.getCredential(ctx("tenant-b"), "openai");
  assert.equal(a?.headers.Authorization, "Bearer key-A");
  assert.equal(b?.headers.Authorization, "Bearer key-B");
});

test("unknown tenant/provider pair -> null", async () => {
  const resolver = new InMemoryTenantResolver();
  resolver.seed("tenant-a", "openai", { headers: { Authorization: "Bearer key-A" } });
  assert.equal(await resolver.getCredential(ctx("tenant-b"), "openai"), null);
  assert.equal(await resolver.getCredential(ctx("tenant-a"), "anthropic"), null);
});

test("connectionId scopes credentials within one tenant", async () => {
  const resolver = new InMemoryTenantResolver();
  resolver.seed("tenant-a", "openai", { headers: { Authorization: "Bearer conn-1" } }, "c1");
  resolver.seed("tenant-a", "openai", { headers: { Authorization: "Bearer conn-2" } }, "c2");
  assert.equal(
    (await resolver.getCredential(ctx("tenant-a"), "openai", "c1"))?.headers.Authorization,
    "Bearer conn-1"
  );
  assert.equal(await resolver.getCredential(ctx("tenant-a"), "openai", "c9"), null);
});

test("LocalEnvResolver fallback returns the shared connection", async () => {
  const resolver = new LocalEnvResolver(async () => ({ apiKey: "shared-key" }));
  const hit = await resolver.getCredential(ctx("any-tenant"), "openai");
  assert.equal(hit?.headers.Authorization, "Bearer shared-key");
});

test("LocalEnvResolver returns null when no connection exists", async () => {
  const resolver = new LocalEnvResolver(async () => null);
  assert.equal(await resolver.getCredential(ctx("any-tenant"), "openai"), null);
});

test("LocalEnvResolver loader failure resolves to null, never throws", async () => {
  const resolver = new LocalEnvResolver(async () => {
    throw new Error("db down\nat /secret/path/stack.ts:1:1");
  });
  assert.equal(await resolver.getCredential(ctx("any-tenant"), "openai"), null);
});
