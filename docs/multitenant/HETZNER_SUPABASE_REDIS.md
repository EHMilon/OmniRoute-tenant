# Multitenant deploy: Hetzner CX23 + Supabase + Redis

Phase 2 shim status: virtual keys + rate limiting run **in-memory only**.
No SQLite schema change, no new dependency. This doc is the runbook for
graduating the shim to production on a Hetzner CX23 box with Supabase
(external, managed) and Redis (compose-internal).

All paths/endpoints below were verified with `rg` on this branch. Anything
marked FUTURE does not exist yet and must not be referenced as live code.

## 1. Identity model

| Caller               | Credential              | Verifier                                                      |
| -------------------- | ----------------------- | ------------------------------------------------------------- |
| Human (dashboard)    | Supabase Auth JWT       | Supabase (FUTURE wiring)                                      |
| Machine (API client) | `sk-or-...` virtual key | `src/server/tenant/virtualKeys.ts` → FUTURE `api_keys` lookup |

Rules: store only SHA-256 (`key_hash`), show the secret once at mint,
never log secrets, Zod-validate all key inputs.

## 2. Docker Compose topology

Verified in `docker-compose.yml` / `docker-compose.prod.yml` / `Dockerfile`:

- `omniroute` app (default `PORT=20128`, see `.env.example`).
- `redis` service (`redis:8.6.5-alpine`, reachable as `redis:6379` on the
  compose network; host bind is loopback-only by default).
- `REDIS_URL` defaults to `redis://redis:6379` in compose (`docker-compose.yml:50`).
- Caddy acts as upstream load balancer / TLS terminator (per compose comment
  `docker-compose.yml:31`); app + Redis stay on the internal network.
- Supabase is **external** (managed cloud) — never a compose service. Only a
  URL + anon/service key in env reaches it.

## 3. Supabase DDL (FUTURE — not applied)

```sql
create table profiles (
  user_id uuid primary key references auth.users (id),
  stripe_customer_id text,
  created_at timestamptz default now()
);
create table provider_connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles (user_id),
  provider text not null,
  -- AES-256-GCM ciphertext. Decrypt server-side only; NEVER expose via Data API.
  encrypted_credentials bytea not null,
  created_at timestamptz default now()
);
create table api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles (user_id),
  key_hash text unique not null, -- hex SHA-256 of the sk-or- secret
  prefix text not null,          -- e.g. sk-or-XXXXXXXX (display only)
  name text,
  revoked_at timestamptz,
  created_at timestamptz default now()
);
create table usage_events (
  id bigint generated always as identity primary key,
  user_id uuid not null references profiles (user_id),
  api_key_id uuid references api_keys (id),
  model text not null,
  prompt_tokens int not null default 0,
  completion_tokens int not null default 0,
  created_at timestamptz default now()
);
create table subscriptions (
  user_id uuid primary key references profiles (user_id),
  plan text not null default 'free',
  rpm int not null default 60,
  tpm int not null default 100000,
  concurrency int not null default 4,
  updated_at timestamptz default now()
);
```

RLS notes: enable RLS on all five tables; `provider_connections` gets **no**
SELECT policy for the anon role (server service-role only); `api_keys` rows
are selectable only by their owning `user_id` (`auth.uid() = user_id`) and
never return `key_hash` to the client; `usage_events` are insert-only from
the service role, read-only for owners.

Existing local overlap: `src/lib/db/apiKeys.ts` already manages a
single-node SQLite `api_keys` table (with `key_hash` + timing-safe compare).
That stays for self-host; the Supabase table above is the hosted-multitenant
counterpart. Phase 2 touches neither.

## 4. Request lifecycle (10 steps)

1. Caddy terminates TLS, forwards to `omniroute:20128`.
2. Route `src/app/api/v1/chat/completions/route.ts`: CORS → Zod validation.
3. Auth: Supabase JWT (humans) or `sk-or-` lookup (machines, FUTURE DB read).
4. Route guard `src/server/authz/routeGuard.ts` (`LOCAL_ONLY_API_PREFIXES`).
5. `InMemoryRateLimiter.check()` (`src/server/tenant/rateLimit.ts`):
   per-key + per-tenant + per-IP buckets; deny → 429 + `retryAfterMs`.
6. `open-sse/handlers/chatCore.ts`: cache → combo routing → executor.
7. Upstream fetch with retry/backoff; response translation / SSE stream.
8. Token usage captured in-memory during the stream.
9. Background flush writes `usage_events` (FUTURE) — never blocks the stream.
10. Health signal via `src/app/api/monitoring/health/route.ts`.

## 5. Rate-limit layering (verified)

- Shim: `src/server/tenant/rateLimit.ts` (`InMemoryRateLimiter`, sliding 60s).
- Existing: `src/shared/utils/rateLimiter.ts` (REDIS optional, in-memory
  fallback, `REDIS_KEY_PREFIX` namespacing) — the convention the Redis
  graduation follows.
- Stub: `RedisRateLimiter` (same interface, throws `NOT_CONFIGURED` until a
  backend exists; `REDIS_URL` is the only env gate; no `redis` dep added).

## 6. Abuse table

| Abuse                       | Mitigation (shim → production)                                         |
| --------------------------- | ---------------------------------------------------------------------- |
| Key sharing / leak          | 8-char visible prefix identifies the key; revoke by id; rotate         |
| Burst / scrape              | Per-key + per-IP RPM deny with `retryAfterMs` (429)                    |
| Noisy tenant starves others | Per-tenant bucket isolates blast radius                                |
| Token-burn attack           | `tpm` cap per window; `concurrency` cap per key                        |
| Stolen DB dump              | Only `key_hash` stored; hashes are non-reversible                      |
| Redis down                  | Fall back to `InMemoryRateLimiter` (degraded, single-replica accurate) |

## 7. Scaling path: 1 → N replicas

1. Single CX23: in-memory limiter is exact; Redis optional.
2. Add replicas behind Caddy: set `REDIS_URL=redis://redis:6379` on all
   replicas; implement `RedisRateLimiter` with Lua-based sliding windows
   under the existing `REDIS_KEY_PREFIX` convention.
3. Supabase Auth + `api_keys`/`subscriptions` become the source of truth for
   limits (`rpm`/`tpm`/`concurrency` per plan).
4. `usage_events` flush moves to a queue worker (batch insert, idempotent).
5. Redis persistence (`--save 60 1`, already in compose) covers restarts;
   limiter state is reconstructible from traffic, so loss is acceptable.
