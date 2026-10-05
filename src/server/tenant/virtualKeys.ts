/**
 * Virtual API keys for the multitenant shim (Phase 2).
 *
 * Humans auth with Supabase Auth (JWT). Machines auth with `sk-or-...`
 * virtual keys minted here. Only the SHA-256 hash is ever persisted;
 * the plaintext secret is shown exactly once at mint time and never logged.
 *
 * Future Supabase table (NOT created here — no DB change in this phase):
 *   api_keys(user_id uuid, key_hash text unique, prefix text, revoked_at timestamptz)
 * The {@link VirtualKeyRecord} shape maps 1:1 onto that row so the
 * in-memory store can be swapped for Supabase without changing callers.
 *
 * Rules: no eval/new Function, Zod-validate all inputs, never log secrets.
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";

/** Prefix every minted secret carries. */
export const VIRTUAL_KEY_PREFIX = "sk-or-";
/** Visible characters after the prefix (safe for dashboards/logs). */
export const VISIBLE_PREFIX_CHARS = 8;
/** Random bytes per secret (256-bit). */
const SECRET_BYTES = 32;

/** Persisted shape. `keyHash` is hex SHA-256 of the secret — never the secret. */
export interface VirtualKeyRecord {
  id: string;
  userId: string;
  /** e.g. `sk-or-XXXXXXXX` — first 8 secret chars, safe to display/log. */
  prefix: string;
  keyHash: string;
  name: string | null;
  revokedAt: string | null;
  createdAt: string;
}

/** Row shape of the future Supabase `api_keys` table. Same fields, snake_case. */
export interface SupabaseApiKeyRow {
  id: string;
  user_id: string;
  key_hash: string;
  prefix: string;
  name: string | null;
  revoked_at: string | null;
  created_at: string;
}

export const createVirtualKeySchema = z.object({
  userId: z.string().min(1).max(128),
  name: z.string().min(1).max(64).optional(),
});

export const revokeVirtualKeySchema = z.object({
  keyId: z.string().min(1).max(128),
  userId: z.string().min(1).max(128),
});

export type CreateVirtualKeyInput = z.infer<typeof createVirtualKeySchema>;
export type RevokeVirtualKeyInput = z.infer<typeof revokeVirtualKeySchema>;

/** SHA-256 hex digest of a plaintext secret. */
export function sha256Hex(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex");
}

/**
 * Timing-safe comparison of a candidate secret against a stored hash.
 * Returns false (no throw) on shape/length mismatch.
 */
export function verifyVirtualKey(secret: string, hash: string): boolean {
  if (typeof secret !== "string" || typeof hash !== "string") return false;
  if (!secret || !hash) return false;
  const candidate = sha256Hex(secret);
  const a = Buffer.from(candidate, "hex");
  const b = Buffer.from(hash, "hex");
  if (a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(a, b);
}

export interface MintedVirtualKey {
  id: string;
  /** First 14 chars (`sk-or-` + 8 visible). Safe to display. */
  prefix: string;
  /** Plaintext secret — returned ONCE. Never persist or log. */
  secretOnce: string;
  /** SHA-256 hex of `secretOnce` — this is what gets stored. */
  sha256Hash: string;
}

/** Mint a new virtual key. The secret is unrecoverable after this call. */
export function mintVirtualKey(): MintedVirtualKey {
  const secretOnce = `${VIRTUAL_KEY_PREFIX}${randomBytes(SECRET_BYTES).toString("base64url")}`;
  return {
    id: randomUUID(),
    prefix: secretOnce.slice(0, VIRTUAL_KEY_PREFIX.length + VISIBLE_PREFIX_CHARS),
    secretOnce,
    sha256Hash: sha256Hex(secretOnce),
  };
}

export function toSupabaseRow(record: VirtualKeyRecord): SupabaseApiKeyRow {
  return {
    id: record.id,
    user_id: record.userId,
    key_hash: record.keyHash,
    prefix: record.prefix,
    name: record.name,
    revoked_at: record.revokedAt,
    created_at: record.createdAt,
  };
}

/**
 * In-memory store ONLY (Phase 2 shim). No SQLite change, no Supabase call.
 * Swap for the `api_keys` table when the Supabase backend lands.
 */
export class InMemoryVirtualKeyStore {
  private byId = new Map<string, VirtualKeyRecord>();
  private byHash = new Map<string, VirtualKeyRecord>();

  /** Mint + store. Returns the secret once — the caller delivers it. */
  create(input: CreateVirtualKeyInput): { record: VirtualKeyRecord; secretOnce: string } {
    const parsed = createVirtualKeySchema.parse(input);
    const minted = mintVirtualKey();
    const record: VirtualKeyRecord = {
      id: minted.id,
      userId: parsed.userId,
      prefix: minted.prefix,
      keyHash: minted.sha256Hash,
      name: parsed.name ?? null,
      revokedAt: null,
      createdAt: new Date().toISOString(),
    };
    this.byId.set(record.id, record);
    this.byHash.set(record.keyHash, record);
    return { record, secretOnce: minted.secretOnce };
  }

  /** Resolve a presenting secret to its live record, or null. */
  verify(secret: string): VirtualKeyRecord | null {
    if (typeof secret !== "string" || !secret.startsWith(VIRTUAL_KEY_PREFIX)) return null;
    for (const record of this.byHash.values()) {
      if (record.revokedAt) continue;
      if (verifyVirtualKey(secret, record.keyHash)) return record;
    }
    return null;
  }

  /** Revoke by id (owner-scoped). Returns false when not found/not owned. */
  revoke(input: RevokeVirtualKeyInput): boolean {
    const parsed = revokeVirtualKeySchema.parse(input);
    const record = this.byId.get(parsed.keyId);
    if (!record || record.userId !== parsed.userId || record.revokedAt) return false;
    record.revokedAt = new Date().toISOString();
    return true;
  }

  getById(keyId: string): VirtualKeyRecord | null {
    return this.byId.get(keyId) ?? null;
  }

  get size(): number {
    return this.byId.size;
  }
}
