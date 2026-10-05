/**
 * Phase 1 tenant context extraction — missing/invalid input yields null.
 *
 * Runner: node --import tsx/esm --test tests/unit/tenant/context.test.ts
 */
import test from "node:test";
import assert from "node:assert/strict";
import { extractTenantContext } from "../../../src/server/tenant/context.ts";

function req(headers: Record<string, string>): Request {
  return new Request("http://localhost/v1/chat/completions", { headers });
}

test("returns a context for valid tenant id + bearer key", () => {
  const ctx = extractTenantContext(
    req({ "x-tenant-id": "acme-01", authorization: "Bearer secret-key" })
  );
  assert.ok(ctx);
  assert.equal(ctx?.tenantId, "acme-01");
  assert.equal(ctx?.storageMode, "LOCAL");
});

test("missing tenant header -> null", () => {
  assert.equal(extractTenantContext(req({ authorization: "Bearer secret-key" })), null);
});

test("missing bearer key -> null", () => {
  assert.equal(extractTenantContext(req({ "x-tenant-id": "acme-01" })), null);
});

test("malformed bearer scheme -> null", () => {
  assert.equal(
    extractTenantContext(req({ "x-tenant-id": "acme-01", authorization: "Basic dXNlcjpwYXNz" })),
    null
  );
});

test("invalid tenant id format -> null", () => {
  for (const bad of ["a", "has space", "semi;colon", "../escape"]) {
    assert.equal(
      extractTenantContext(req({ "x-tenant-id": bad, authorization: "Bearer secret-key" })),
      null,
      `expected null for ${JSON.stringify(bad)}`
    );
  }
});

test("empty bearer token -> null", () => {
  assert.equal(
    extractTenantContext(req({ "x-tenant-id": "acme-01", authorization: "Bearer   " })),
    null
  );
});
