/**
 * Phase 1 multi-tenant foundation — shared tenant types.
 *
 * NEW-file shim only: nothing in the existing request pipeline imports this
 * yet. Callers opt in per-route (Phase 2) via `extractTenantContext`.
 */
import { z } from "zod";

/** Where a tenant's credentials live. LOCAL = single-operator DB (default). */
export const storageModeSchema = z.enum(["LOCAL", "CLOUD", "SYNC"]);
export type StorageMode = z.infer<typeof storageModeSchema>;

/** Tenant ids travel in the `x-tenant-id` header: bounded, no controls. */
export const tenantIdSchema = z
  .string()
  .min(2)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9_-]*$/i, "invalid tenant id format");

export const tenantContextSchema = z.object({
  tenantId: tenantIdSchema,
  userId: z.string().min(1).max(128).nullable().default(null),
  apiKeyId: z.string().min(1).max(128).nullable().default(null),
  plan: z.string().min(1).max(64).default("default"),
  storageMode: storageModeSchema.default("LOCAL"),
});

/** Per-request tenant scope. userId/apiKeyId stay null until auth resolves them. */
export type TenantContext = z.infer<typeof tenantContextSchema>;

export const credentialDescriptorSchema = z.object({
  provider: z.string().min(1).max(64),
  connectionId: z.string().min(1).max(128),
  credentialType: z.enum(["api_key", "oauth", "cookie"]).default("api_key"),
});

/** Identifies one upstream credential slot for a provider. */
export type CredentialDescriptor = z.infer<typeof credentialDescriptorSchema>;
