/**
 * Phase 1 multi-tenant foundation — credential resolution.
 *
 * `CredentialResolver` maps (tenant, provider) -> upstream auth headers.
 * `LocalEnvResolver` is the single-tenant fallback: it reads the existing
 * `provider_connections` table via `src/lib/db/providers.ts` with no schema
 * change. `InMemoryTenantResolver` is a strict per-tenant map for tests.
 *
 * Rule #12: resolver failures resolve to `null`; any surfaced text goes
 * through `sanitizeErrorMessage`. Raw `err.stack`/messages never escape.
 */
import { sanitizeErrorMessage } from "@omniroute/open-sse/utils/error.ts";
import type { TenantContext } from "./types";

export interface ResolvedCredential {
  headers: Record<string, string>;
  expiresAt?: string;
}

export interface CredentialResolver {
  getCredential(
    ctx: TenantContext,
    provider: string,
    connectionId?: string
  ): Promise<ResolvedCredential | null>;
}

type ConnectionRow = {
  id?: unknown;
  apiKey?: unknown;
  accessToken?: unknown;
  cookie?: unknown;
};

type ConnectionLoader = (provider: string, connectionId?: string) => Promise<ConnectionRow | null>;

/** Default loader: single-tenant DB read, lazy import keeps the shim light. */
async function loadSingleTenantConnection(
  provider: string,
  connectionId?: string
): Promise<ConnectionRow | null> {
  const db = await import("@/lib/db/providers.ts");
  if (connectionId) {
    return (await db.getProviderConnectionById(connectionId)) as ConnectionRow | null;
  }
  const rows = (await db.getProviderConnections(
    { provider, isActive: true },
    1
  )) as ConnectionRow[];
  return rows[0] ?? null;
}

function toHeaders(row: ConnectionRow): Record<string, string> | null {
  const key =
    typeof row.apiKey === "string" && row.apiKey.length > 0
      ? row.apiKey
      : typeof row.accessToken === "string" && row.accessToken.length > 0
        ? row.accessToken
        : null;
  if (key) return { Authorization: "Bearer " + key };
  if (typeof row.cookie === "string" && row.cookie.length > 0) {
    return { Cookie: row.cookie };
  }
  return null;
}

/**
 * Single-tenant fallback. Ignores `ctx.tenantId` for lookup (one shared
 * credential pool) — per-tenant scoping arrives in Phase 2 with a tenant
 * column. Accepts an injected loader so tests never touch SQLite.
 */
export class LocalEnvResolver implements CredentialResolver {
  private readonly loader: ConnectionLoader;

  constructor(loader: ConnectionLoader = loadSingleTenantConnection) {
    this.loader = loader;
  }

  async getCredential(
    _ctx: TenantContext,
    provider: string,
    connectionId?: string
  ): Promise<ResolvedCredential | null> {
    try {
      if (!provider || provider.length > 64) return null;
      const row = await this.loader(provider, connectionId);
      if (!row) return null;
      const headers = toHeaders(row);
      return headers ? { headers } : null;
    } catch (err) {
      sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
      return null;
    }
  }
}

/** Strict per-tenant in-memory store. Keys are always tenant-scoped. */
export class InMemoryTenantResolver implements CredentialResolver {
  private readonly store = new Map<string, ResolvedCredential>();

  private static key(tenantId: string, provider: string, connectionId?: string): string {
    return JSON.stringify([tenantId, provider, connectionId ?? ""]);
  }

  seed(
    tenantId: string,
    provider: string,
    credential: ResolvedCredential,
    connectionId?: string
  ): void {
    this.store.set(InMemoryTenantResolver.key(tenantId, provider, connectionId), credential);
  }

  async getCredential(
    ctx: TenantContext,
    provider: string,
    connectionId?: string
  ): Promise<ResolvedCredential | null> {
    try {
      if (!ctx?.tenantId || !provider) return null;
      const hit = this.store.get(InMemoryTenantResolver.key(ctx.tenantId, provider, connectionId));
      return hit ? { headers: { ...hit.headers }, expiresAt: hit.expiresAt } : null;
    } catch (err) {
      sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
      return null;
    }
  }
}
