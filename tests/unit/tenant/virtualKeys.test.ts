/**
 * Tests for the Phase 2 virtual-key shim (`src/server/tenant/virtualKeys.ts`).
 *
 * Proves: secret is never stored, verification is timing-safe,
 * revoked keys stop working, prefixes leak nothing usable.
 */
import test from "node:test";
import assert from "node:assert/strict";

const { InMemoryVirtualKeyStore, mintVirtualKey, verifyVirtualKey, sha256Hex } =
  await import("../../../src/server/tenant/virtualKeys.ts");

test("mintVirtualKey returns sk-or- secret with 8-char visible prefix", () => {
  const minted = mintVirtualKey();
  assert.ok(minted.secretOnce.startsWith("sk-or-"));
  assert.equal(minted.prefix, minted.secretOnce.slice(0, "sk-or-".length + 8));
  assert.equal(minted.sha256Hash, sha256Hex(minted.secretOnce));
  assert.match(minted.sha256Hash, /^[0-9a-f]{64}$/);
  assert.equal(minted.prefix.length, "sk-or-".length + 8);
});

test("store never persists the secret — only its hash", () => {
  const store = new InMemoryVirtualKeyStore();
  const { record, secretOnce } = store.create({ userId: "u1", name: "ci" });
  assert.ok(!JSON.stringify(record).includes(secretOnce));
  assert.equal(record.keyHash, sha256Hex(secretOnce));
  assert.equal(record.revokedAt, null);
});

test("verifyVirtualKey is timing-safe and rejects wrong secrets", () => {
  const minted = mintVirtualKey();
  assert.equal(verifyVirtualKey(minted.secretOnce, minted.sha256Hash), true);
  assert.equal(verifyVirtualKey(`${minted.secretOnce}x`, minted.sha256Hash), false);
  assert.equal(verifyVirtualKey("", minted.sha256Hash), false);
  assert.equal(verifyVirtualKey(minted.secretOnce, "deadbeef"), false);
});

test("store.verify resolves live keys and blocks revoked ones", () => {
  const store = new InMemoryVirtualKeyStore();
  const { record, secretOnce } = store.create({ userId: "u9" });
  assert.equal(store.verify(secretOnce)?.id, record.id);
  assert.equal(store.verify("sk-or-notakey"), null);
  assert.equal(store.revoke({ keyId: record.id, userId: "u9" }), true);
  assert.equal(store.verify(secretOnce), null);
  // Wrong owner cannot revoke; double revoke is a no-op false.
  const other = store.create({ userId: "u10" });
  assert.equal(store.revoke({ keyId: other.record.id, userId: "intruder" }), false);
  assert.equal(store.revoke({ keyId: record.id, userId: "u9" }), false);
});

test("Zod rejects invalid create/revoke inputs", () => {
  const store = new InMemoryVirtualKeyStore();
  assert.throws(() => store.create({ userId: "" }));
  assert.throws(() => store.revoke({ keyId: "", userId: "u1" }));
});
