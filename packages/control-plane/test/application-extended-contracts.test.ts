import { describe, expect, it } from "vitest";
import {
  APPLICATION_CLIENT_KINDS,
  OIDC_RP_CLIENT_TYPES,
  OIDC_RP_PKCE_METHODS,
  validateOidcRpClient,
  type OpaqueClientSession,
  type PublicPlatformLoginResultDto,
  type WebviewTicket,
  type WechatComponentPlatformBinding,
} from "@getbrick/idaas-contracts";
import {
  APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_VERSION,
  APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_VERSION,
  APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_VERSION,
  APPLICATION_MANAGEMENT_MIGRATION_VERSION,
  createApplicationManagementAdditiveMigrationChecksum,
  createApplicationManagementAdditiveMigrationSql,
  createClientAuthBffStateMigrationSql,
  createApplicationManagementMigrationSql,
  createCompleteApplicationManagementMigrationSql,
  createPlatformLoginStateTableMigrationSql,
  createApplicationManagementReturnToMigrationChecksum,
  createApplicationManagementReturnToMigrationSql,
  applyVersionedApplicationManagementMigrations,
  getApplicationManagementAdditiveMigrationDefinition,
  getApplicationManagementClientAuthBffMigrationDefinition,
  getApplicationManagementMigrationDefinition,
  getApplicationManagementMigrations,
  getApplicationManagementReturnToMigrationDefinition,
} from "../src/application-migration.js";
import {
  createAdditiveMigrationDefinition,
  createMigrationSeries,
  migrationChecksum,
  type MigrationSqlExecutor,
} from "../src/migration-coordinator.js";

import {
  InMemoryOpaqueClientSessionRepository,
  hashClientSessionReference,
} from "../src/client-session-repository.js";
import {
  InMemoryWebviewTicketRepository,
  hashWebviewTicket,
} from "../src/webview-ticket-repository.js";

const reference = "a".repeat(43);
const ticket = "b".repeat(43);

function publicResult(): PublicPlatformLoginResultDto {
  return {
    user: { id: "user-1", name: "User", email: null, emailVerified: false },
    session: { sessionReference: reference, clientKind: "mp_weixin", expiresAt: "2026-01-01T00:00:00.000Z" },
    created: true,
    linked: false,
    client: "mp_weixin",
  };
}

describe("strict application contracts", () => {
  it("keeps the four client kinds and RP defaults explicit", () => {
    expect(APPLICATION_CLIENT_KINDS).toEqual(["web", "webview", "mp_weixin", "native"]);
    expect(OIDC_RP_CLIENT_TYPES).toEqual(["web"]);
    expect(OIDC_RP_PKCE_METHODS).toEqual(["S256"]);
    expect(validateOidcRpClient({ clientId: "rp-1", redirectUris: ["https://rp.example.test/callback"] })).toMatchObject({
      clientType: "web",
      clientKind: "web",
      redirectUriPolicy: "exact",
      requirePkce: true,
      pkceMethod: "S256",
      consent: { required: true, mode: "explicit" },
    });
    expect(() => validateOidcRpClient({ clientId: "rp-1", redirectUris: ["http://rp.example.test/callback"] })).toThrow();
    expect(() => validateOidcRpClient({ clientId: "rp-1", redirectUris: ["https://rp.example.test/callback"], requirePkce: false })).toThrow();
    expect(() => validateOidcRpClient({ clientId: "rp-1", redirectUris: ["https://rp.example.test/callback"], consent: "implicit" })).toThrow();
  });

  it("describes public sessions, tickets and component bindings without provider secrets", () => {
    const session: OpaqueClientSession = {
      sessionReference: reference,
      clientKind: "mp_weixin",
      expiresAt: "2026-01-01T00:00:00.000Z",
      tokenType: "Bearer",
    };
    const webview: WebviewTicket = {
      ticketReference: ticket,
      clientKind: "webview",
      redirectUri: "https://rp.example.test/webview",
      expiresAt: "2026-01-01T00:00:00.000Z",
    };
    const binding: WechatComponentPlatformBinding = {
      componentAppId: "wx-component",
      authorizedAppId: "wx-authorizer-1",
      componentAppSecretRef: "vault://wechat/component",
      status: "active",
    };
    const result = publicResult();
    expect(session.sessionReference).toBe(reference);
    expect(webview.clientKind).toBe("webview");
    expect(binding.authorizedAppId).toBe("wx-authorizer-1");
    expect(JSON.stringify({ session, webview, result })).not.toContain("access_token");
  });
});

describe("additive application migration", () => {
  it("keeps foundation and additive checksums while adding returnTo and BFF state as version 5", () => {
    const foundation = getApplicationManagementMigrationDefinition();
    const additive = getApplicationManagementAdditiveMigrationDefinition();
    const returnTo = getApplicationManagementReturnToMigrationDefinition();
    const clientAuthBff = getApplicationManagementClientAuthBffMigrationDefinition({ mode: "shared" });
    const migrations = getApplicationManagementMigrations();
    expect(foundation.version).toBe(APPLICATION_MANAGEMENT_MIGRATION_VERSION);
    expect(foundation.checksum).toBe(migrationChecksum(createApplicationManagementMigrationSql()));
    expect(additive.version).toBe(APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_VERSION);
    expect(returnTo.version).toBe(APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_VERSION);
    expect(clientAuthBff.version).toBe(APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_VERSION);
    expect(createApplicationManagementMigrationSql()).not.toContain("client_kind");
    expect(migrations.map((migration) => migration.version)).toEqual([2, 3, 4, 5]);
    expect(getApplicationManagementMigrations({ includeAdditive: false }).map((migration) => migration.version)).toEqual([2]);
    expect(migrations[0]?.checksum).toBe(foundation.checksum);
    expect(migrations[1]?.checksum).toBe(additive.checksum);
    expect(createApplicationManagementAdditiveMigrationChecksum()).toBe(additive.checksum);
    expect(createApplicationManagementReturnToMigrationChecksum()).toBe(returnTo.checksum);
    expect(clientAuthBff.checksum).toBe(migrationChecksum(createClientAuthBffStateMigrationSql({ mode: "shared" })));
    expect(createApplicationManagementReturnToMigrationSql()).toContain('ALTER TABLE "gb_idaas_platform_login_state" ADD COLUMN IF NOT EXISTS "return_to" TEXT');
    expect(additive.sql).toContain('"client_kind"');
    expect(additive.sql).toContain('"gb_idaas_client_session"');
    expect(additive.sql).toContain('"gb_idaas_webview_ticket"');
    expect(additive.sql).toContain('"authorized_app_id"');
    expect(additive.sql).not.toContain('ALTER TABLE "gb_idaas_application" DROP COLUMN');
    expect(clientAuthBff.sql).toContain('"gb_idaas_client_auth_bff_state"');
    expect(clientAuthBff.sql).toContain('CREATE INDEX IF NOT EXISTS');
     expect(clientAuthBff.sql).toContain('PRIMARY KEY ("tenant_id", "state_hash")');
     expect(clientAuthBff.sql).toContain('CHECK ("expires_at" > "created_at")');
     expect(clientAuthBff.sql).toContain('FORCE ROW LEVEL SECURITY');
  });

  it("supports custom additive tables and RLS without changing the foundation", () => {
    const foundation = createApplicationManagementMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    const additive = createApplicationManagementAdditiveMigrationSql({
      mode: "shared",
      tenantId: "tenant-a",
      clientSessionTable: "custom_client_session",
      webviewTicketTable: "custom_webview_ticket",
    });
    expect(foundation).not.toContain("custom_client_session");
    expect(additive).toContain('"custom_client_session"');
    expect(additive).toContain('"custom_webview_ticket"');
     expect(additive).toContain('"custom_client_session_tenant"');
     expect(additive).toContain('"custom_webview_ticket_tenant"');
     const clientAuthBff = createClientAuthBffStateMigrationSql({
       mode: "shared",
       tenantId: "tenant-a",
       schema: "tenant_a",
       clientAuthBffStateTable: "custom_bff_state",
     });
     expect(clientAuthBff).toContain('"tenant_a"."custom_bff_state"');
     expect(clientAuthBff).toContain('FORCE ROW LEVEL SECURITY');
     expect(clientAuthBff).toContain('current_setting(\'app.tenant_id\', true)');
  });

  it("includes returnTo in fresh-schema SQL without changing historical definitions", () => {
    const fresh = createCompleteApplicationManagementMigrationSql();
     expect(fresh).toContain('"return_to" TEXT');
     expect(fresh).toContain('"gb_idaas_client_auth_bff_state"');
     expect(fresh).toContain('CREATE INDEX IF NOT EXISTS');
     expect(fresh).toContain('ADD COLUMN IF NOT EXISTS "return_to" TEXT');
    expect(createPlatformLoginStateTableMigrationSql()).toContain('"return_to" TEXT');
    expect(getApplicationManagementMigrationDefinition().checksum).toBe("63acc73e0a395a3d3051a3e6859318db49b39afb1411a1f58b0f17693deba8dd");
    expect(getApplicationManagementAdditiveMigrationDefinition().checksum).toBe("168f7c478d32f1068cfd8225b11cf0b09f7597d4b78327c960fd39e5ce50056a");
  });

  it("runs the additive series through the versioned coordinator", async () => {
    const applied = new Map<string, { version: number; name: string; checksum: string; scope: string }>();
    const executor: MigrationSqlExecutor = {
      query: async (text: string, values: unknown[] = []) => {
        if (text.includes('FROM "gb_idaas_schema_migration"')) return { rows: [...applied.values()] };
        if (text.includes('INSERT INTO "gb_idaas_schema_migration"')) {
          applied.set(`${String(values[9])}:${String(values[0])}`, {
            version: Number(values[0]),
            name: String(values[1]),
            checksum: String(values[2]),
            scope: String(values[9]),
          });
          return { rowCount: 1, rows: [] };
        }
        return { rows: [] };
      },
      transaction: async <T>(callback: (value: typeof executor) => Promise<T>) => callback(executor),
    };
     const first = await applyVersionedApplicationManagementMigrations(executor, { migrationLockKey: "extended" });
     expect(first.applied.map((migration) => migration.version)).toEqual([2, 3, 4, 5]);
     const second = await applyVersionedApplicationManagementMigrations(executor, { migrationLockKey: "extended" });
     expect(second.applied).toHaveLength(0);
     expect(second.skipped).toHaveLength(4);
  });

  it("validates an ordered migration series with immutable checksums", () => {
    const first = createAdditiveMigrationDefinition(1, "foundation", "CREATE TABLE first (id TEXT);", {}, "scope", []);
    const second = createAdditiveMigrationDefinition(2, "additive", "ALTER TABLE first ADD COLUMN value TEXT;", {}, "scope", [1]);
    const series = createMigrationSeries([first, second]);
    expect(series.migrations.map((migration) => migration.version)).toEqual([1, 2]);
    expect(series.preserveChecksums).toBe(true);
    expect(() => createMigrationSeries([second, first])).not.toThrow();
    expect(() => createMigrationSeries([first, { ...first, sql: "SELECT 1;" }])).toThrow();
  });
});

describe("opaque repositories", () => {
  it("stores only a hash and enforces native client kinds", () => {
    const repository = new InMemoryOpaqueClientSessionRepository({ tenantId: "tenant-a" });
    const issued = repository.issue({
      applicationId: "app-1",
      clientId: "client-1",
      clientKind: "mp_weixin",
      userId: "user-1",
      sessionReference: reference,
    });
    expect(issued.session.sessionReference).toBe(reference);
    expect(issued.record.sessionHash).toBe(hashClientSessionReference(reference));
    expect(repository.snapshot()[0]?.sessionHash).not.toBe(reference);
    expect(repository.find(reference)?.userId).toBe("user-1");
    expect(() => repository.issue({ applicationId: "app-1", clientId: "client-1", clientKind: "web" as never, userId: "user-1", sessionReference: "c".repeat(43) })).toThrow();
  });

  it("consumes a webview ticket once and stores its hash", () => {
    const repository = new InMemoryWebviewTicketRepository({ tenantId: "tenant-a" });
    const issued = repository.issue({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri: "https://rp.example.test/webview",
      ticketReference: ticket,
    });
    expect(issued.record.ticketHash).toBe(hashWebviewTicket(ticket));
    expect(repository.consume({ ticketReference: ticket })?.status).toBe("consumed");
    expect(repository.consume({ ticketReference: ticket })).toBeUndefined();
  });
});
