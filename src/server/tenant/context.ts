/**
 * Phase 1 multi-tenant foundation — per-request tenant extraction.
 *
 * Reads `x-tenant-id` plus the existing Bearer API key. Bearer parsing mirrors
 * the `Bearer ` branch of `extractApiKey` in `src/sse/services/auth.ts` but is
 * done locally so this shim stays free of that module's DB-backed import
 * graph. Missing/invalid input returns `null`; the caller answers 401.
 */
import { tenantContextSchema, tenantIdSchema, type TenantContext } from "./types";

function readHeader(req: Request, name: string): string | null {
  const direct = req.headers.get(name);
  if (typeof direct === "string" && direct.length > 0) return direct;
  const lowered = req.headers.get(name.toLowerCase());
  return typeof lowered === "string" && lowered.length > 0 ? lowered : null;
}

function readBearerKey(req: Request): string | null {
  const header = readHeader(req, "authorization");
  if (!header) return null;
  const trimmed = header.trim();
  if (!trimmed.toLowerCase().startsWith("bearer ")) return null;
  const token = trimmed.slice(7).trim();
  return token.length > 0 ? token : null;
}

/**
 * Build the `TenantContext` for a request, or `null` when the request
 * carries no usable tenant scope (caller must reject with 401).
 */
export function extractTenantContext(req: Request): TenantContext | null {
  try {
    const rawTenantId = readHeader(req, "x-tenant-id");
    const apiKey = readBearerKey(req);
    if (!rawTenantId || !apiKey) return null;
    const tenantId = tenantIdSchema.safeParse(rawTenantId.trim());
    if (!tenantId.success) return null;
    const parsed = tenantContextSchema.safeParse({
      tenantId: tenantId.data,
      userId: null,
      apiKeyId: null,
      plan: "default",
      storageMode: "LOCAL",
    });
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}
