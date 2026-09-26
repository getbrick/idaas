import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { afterAll, expect, it } from "vitest";
import { OpenPlatformPersistence } from "@getbrick/idaas-control-plane/open-platform";
import {
  applyOpenPlatformSmokeMigration,
  createOpenPlatformSmokeAdapter,
  createOpenPlatformSmokePool,
  probeOpenPlatformSmokeDatabase,
} from "../src/open-platform-smoke.js";

const pool = createOpenPlatformSmokePool();
const databaseAvailable = await probeOpenPlatformSmokeDatabase(pool);

if (!databaseAvailable) {
  console.warn("relay lease test skipped: PostgreSQL is unavailable at the configured test database");
}

const databaseIt = databaseAvailable ? it : it.skip;

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

function leaseKey(label: string): string {
  return `getbrick:open-platform:outbox-relay:test:${label}:${randomUUID().replace(/-/gu, "")}`;
}

function relayLease(
  adapter: OpenPlatformPersistence.DatabaseAdapter,
): OpenPlatformPersistence.SqlOpenPlatformRelayLease {
  return new OpenPlatformPersistence.SqlOpenPlatformRelayLease(adapter);
}

function request(key: string, ownerId: string, ttlMs: number) {
  return { key, ownerId, now: new Date().toISOString(), ttlMs };
}

async function applyMigrations(target: Pool): Promise<void> {
  await applyOpenPlatformSmokeMigration(target);
}

afterAll(async () => {
  await pool.end();
});

databaseIt("creates the relay lease table in the additive v5 migration", async () => {
  await applyMigrations(pool);
  const definition = OpenPlatformPersistence.getOpenPlatformRelayLeaseMigrationDefinition({
    mode: "fixed",
    tenantId: "open-platform-smoke",
  });
  expect(definition.version).toBe(5);
  expect(definition.additive).toBe(true);
  expect(definition.requires).toEqual([4]);

  const columns = await pool.query<{ column_name: string }>(
    `SELECT column_name FROM information_schema.columns WHERE table_name = 'gb_open_relay_lease' ORDER BY column_name`,
  );
  expect(columns.rows.map((row) => row.column_name)).toEqual([
    "acquired_at",
    "expires_at",
    "lease_key",
    "owner_id",
    "updated_at",
  ]);
});

databaseIt("is ready only once the relay lease table exists", async () => {
  await applyMigrations(pool);
  const lease = relayLease(createOpenPlatformSmokeAdapter(pool));
  expect(await lease.isReady()).toBe(true);
});

databaseIt("grants a contested lease to exactly one instance", async () => {
  await applyMigrations(pool);
  const key = leaseKey("contended");
  const first = relayLease(createOpenPlatformSmokeAdapter(pool));
  const second = relayLease(createOpenPlatformSmokeAdapter(pool));

  expect((await first.acquire(request(key, "relay_owner_a", 30_000))).held).toBe(true);
  const blocked = await second.acquire(request(key, "relay_owner_b", 30_000));
  expect(blocked.held).toBe(false);
  expect(blocked.ownerId).toBe("relay_owner_a");
  expect(await second.release(request(key, "relay_owner_b", 30_000))).toBe(false);
  expect(await first.release(request(key, "relay_owner_a", 30_000))).toBe(true);
  expect((await second.acquire(request(key, "relay_owner_b", 30_000))).held).toBe(true);
  await second.release(request(key, "relay_owner_b", 30_000));
});

databaseIt("hands the lease over after the ttl expires even when the holder never releases", async () => {
  await applyMigrations(pool);
  const key = leaseKey("ttl-takeover");
  const holder = relayLease(createOpenPlatformSmokeAdapter(pool));
  const standby = relayLease(createOpenPlatformSmokeAdapter(pool));
  const longTtlMs = 30_000;
  const shortTtlMs = 1_000;

  const held = await holder.acquire(request(key, "relay_owner_crashed", longTtlMs));
  expect(held.held).toBe(true);
  expect(Date.parse(held.expiresAt ?? "")).toBeGreaterThan(Date.parse(new Date().toISOString()));
  expect((await standby.acquire(request(key, "relay_owner_standby", longTtlMs))).held).toBe(false);

  expect((await holder.renew(request(key, "relay_owner_crashed", shortTtlMs))).held).toBe(true);
  await sleep(shortTtlMs + 500);

  const takenOver = await standby.acquire(request(key, "relay_owner_standby", shortTtlMs));
  expect(takenOver.held).toBe(true);
  expect(takenOver.ownerId).toBe("relay_owner_standby");
  expect(await standby.holder(key)).toMatchObject({ key, ownerId: "relay_owner_standby" });
  expect((await holder.renew(request(key, "relay_owner_crashed", shortTtlMs))).held).toBe(false);
  await standby.release(request(key, "relay_owner_standby", shortTtlMs));
});

databaseIt("does not leak the lease when acquire and release land on different pooled sessions", async () => {
  await applyMigrations(pool);
  const key = leaseKey("pooled");
  const owner = relayLease(createOpenPlatformSmokeAdapter(pool));
  const other = relayLease(createOpenPlatformSmokeAdapter(pool));
  const ttlMs = 30_000;

  expect((await owner.acquire(request(key, "relay_owner_pooled", ttlMs))).held).toBe(true);

  const clients = await Promise.all(
    Array.from({ length: 8 }, () => pool.connect()),
  );
  try {
    await Promise.all(clients.map((client) => client.query("SELECT pg_sleep(0.02)")));
  } finally {
    for (const client of clients) client.release();
  }

  expect(await owner.release(request(key, "relay_owner_pooled", ttlMs))).toBe(true);
  expect((await other.acquire(request(key, "relay_owner_next", ttlMs))).held).toBe(true);
  await other.release(request(key, "relay_owner_next", ttlMs));
});

databaseIt("keeps separate lease keys independent across environments", async () => {
  await applyMigrations(pool);
  const production = leaseKey("production");
  const staging = leaseKey("staging");
  const first = relayLease(createOpenPlatformSmokeAdapter(pool));
  const second = relayLease(createOpenPlatformSmokeAdapter(pool));

  expect((await first.acquire(request(production, "relay_owner_prod", 30_000))).held).toBe(true);
  expect((await second.acquire(request(production, "relay_owner_prod_2", 30_000))).held).toBe(false);
  expect((await second.acquire(request(staging, "relay_owner_staging", 30_000))).held).toBe(true);
  await first.release(request(production, "relay_owner_prod", 30_000));
  await second.release(request(staging, "relay_owner_staging", 30_000));
});
