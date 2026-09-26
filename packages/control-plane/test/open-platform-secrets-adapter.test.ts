import { afterEach, describe, expect, it, vi } from "vitest";
import {
  InMemorySecretBindingRepository,
  type SecretBindingRecord,
  type SecretBindingResolution,
} from "../src/secret-binding.js";
import {
  InMemoryOpenPlatformRepositories,
  OPEN_PLATFORM_ERROR_CODES,
  OpenPlatformService,
  createDevelopmentOpenPlatformAuthorization,
  createOpenPlatformRequestContextIssuer,
  toOpenPlatformContractError,
} from "../src/open-platform/index.js";
import {
  OPEN_PLATFORM_SECRET_NO_STORE_HEADERS,
  createIdaasSecretResolver,
  createProductionSecretAdapter,
  digestOpenPlatformSecret,
  type OpenPlatformSecretVaultPort,
  type OpenPlatformSecretVaultReadInput,
  type OpenPlatformSecretVaultRevokeInput,
  type OpenPlatformSecretVaultWriteInput,
  type OpenPlatformSecretRevealAuthorizerPort,
  type ProductionSecretAdapter,
} from "../src/open-platform/adapters/secrets/index.js";

const fixedNow = new Date("2030-01-01T00:00:00.000Z");
const tenantRecordId = "tenant_00000000-0000-4000-8000-000000000001";
const organizationRecordId = "org_00000000-0000-4000-8000-000000000002";
const applicationRecordId = "app_00000000-0000-4000-8000-000000000003";

interface VaultValue {
  encoded: string;
  active: boolean;
}

class TestSecretVault implements OpenPlatformSecretVaultPort {
  readonly productionReady: boolean;
  readonly readiness: {
    storage: "memory" | "persistent";
    distributed: boolean;
    ready(): boolean;
  };
  readonly writeInputs: Omit<OpenPlatformSecretVaultWriteInput, "secret">[] = [];
  readonly references: string[] = [];
  readonly revokeInputs: OpenPlatformSecretVaultRevokeInput[] = [];
  readonly revokedReferences: string[] = [];
  readCount = 0;
  readFailureMessage: string | undefined;
  leakReference = false;
  failNextRevoke = false;
  failRevokeCount = 0;
  private sequence = 0;
  private readonly values = new Map<string, VaultValue>();
  private readonly readyResult: boolean;

  constructor(options: {
    productionReady?: boolean;
    persistent?: boolean;
    distributed?: boolean;
    ready?: boolean;
  } = {}) {
    this.productionReady = options.productionReady ?? true;
    const persistent = options.persistent ?? true;
    this.readiness = Object.freeze({
      storage: persistent ? "persistent" as const : "memory" as const,
      distributed: options.distributed ?? persistent,
      ready: () => this.readyResult,
    });
    this.readyResult = options.ready ?? true;
  }

  async write(
    input: OpenPlatformSecretVaultWriteInput,
  ): Promise<{ readonly reference: string }> {
    const { secret, ...safeInput } = input;
    this.writeInputs.push(safeInput);
    this.sequence += 1;
    const reference = this.leakReference
      ? `vault://${input.secret}`
      : `vault://opaque-${this.sequence.toString().padStart(32, "0")}`;
    this.references.push(reference);
    this.values.set(reference, {
      encoded: Buffer.from(secret, "utf8").toString("base64"),
      active: true,
    });
    if (input.revokePrevious && input.previousReference !== undefined) {
      const previous = this.values.get(input.previousReference);
      if (previous !== undefined) previous.active = false;
    }
    return { reference };
  }

  async read(input: OpenPlatformSecretVaultReadInput): Promise<string> {
    this.readCount += 1;
    if (this.readFailureMessage !== undefined) {
      throw new Error(this.readFailureMessage);
    }
    const value = this.values.get(input.reference);
    if (value === undefined || !value.active) {
      throw new Error("vault secret is unavailable");
    }
    return Buffer.from(value.encoded, "base64").toString("utf8");
  }

  async revoke(input: OpenPlatformSecretVaultRevokeInput): Promise<void> {
    this.revokeInputs.push(input);
    if (this.failNextRevoke) {
      this.failNextRevoke = false;
      throw new Error("vault revoke unavailable");
    }
    if (this.failRevokeCount > 0) {
      this.failRevokeCount -= 1;
      throw new Error("vault revoke unavailable");
    }
    const value = this.values.get(input.reference);
    if (value !== undefined) {
      value.active = false;
      value.encoded = "";
    }
    if (!this.revokedReferences.includes(input.reference)) {
      this.revokedReferences.push(input.reference);
    }
  }

  isActive(reference: string): boolean {
    return this.values.get(reference)?.active === true;
  }
}

class PersistentTestSecretBindings extends InMemorySecretBindingRepository {
  readonly productionReady = true;
}

class ResolvedOverrideSecretBindings extends PersistentTestSecretBindings {
  resolution: SecretBindingResolution | undefined;

  override async resolve(
    subjectType: string,
    subjectId: string,
    purpose: string,
    at?: Date,
  ): Promise<SecretBindingResolution | undefined> {
    if (this.resolution !== undefined) return this.resolution;
    return super.resolve(subjectType, subjectId, purpose, at);
  }
}

function allowReveal(): OpenPlatformSecretRevealAuthorizerPort {
  return {
    authorize: vi.fn(() => true),
  };
}

function createHarness(options: {
  tenantId?: string;
  vault?: TestSecretVault;
  authorizer?: OpenPlatformSecretRevealAuthorizerPort;
  bindings?: PersistentTestSecretBindings;
} = {}): {
  adapter: ProductionSecretAdapter;
  vault: TestSecretVault;
  bindings: PersistentTestSecretBindings;
  authorizer: OpenPlatformSecretRevealAuthorizerPort;
} {
  const tenantId = options.tenantId ?? "tenant-secrets";
  const vault = options.vault ?? new TestSecretVault();
  const bindings = options.bindings ?? new PersistentTestSecretBindings({ tenantId });
  const authorizer = options.authorizer ?? allowReveal();
  const adapter = createProductionSecretAdapter({
    vault,
    bindings,
    revealAuthorizer: authorizer,
    clock: () => new Date(),
  });
  return { adapter, vault, bindings, authorizer };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("production open platform secrets adapter", () => {
  it("returns credential plaintext once while storage keeps only digest and reference", async () => {
    const harness = createHarness({ tenantId: "tenant-service" });
    const repositories = new InMemoryOpenPlatformRepositories({
      clock: () => fixedNow,
    });
    await repositories.tenants.create({
      id: tenantRecordId,
      tenantId: "tenant-service",
      kind: "tenant",
      name: "Service tenant",
      status: "published",
      version: 1,
      createdAt: fixedNow.toISOString(),
      updatedAt: fixedNow.toISOString(),
    });
    await repositories.applications.create({
      id: applicationRecordId,
      tenantId: "tenant-service",
      kind: "application",
      organizationId: organizationRecordId,
      name: "Service application",
      status: "published",
      version: 1,
      createdAt: fixedNow.toISOString(),
      updatedAt: fixedNow.toISOString(),
    });
    const service = new OpenPlatformService({
      mode: "test",
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      repositories,
      secretProvider: harness.adapter,
      clock: () => fixedNow,
    });
    const issuer = createOpenPlatformRequestContextIssuer({
      issuerId: "secret-adapter-tests",
      attestation: Object.freeze({ test: true }),
      clock: () => fixedNow,
    });
    const context = issuer.issueDevelopment({
      tenantId: "tenant-service",
      actorId: "actor-secrets",
      requestId: "request-issue",
    });
    const command = {
      tenantId: "tenant-service",
      applicationId: applicationRecordId,
      name: "Service credential",
      scopes: ["orders:read"],
      idempotencyKey: "credential-once",
    } as const;
    const issued = await service.issueCredential(context, command);
    const replayed = await service.issueCredential(context, command);
    if (issued.secret === undefined) throw new Error("secret was not issued");

    expect(issued.secret).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(replayed).toMatchObject({
      credential: { id: issued.credential.id },
      secret: undefined,
      replayed: true,
    });
    expect(harness.vault.writeInputs).toHaveLength(1);

    const stored = await repositories.credentials.get(
      "tenant-service",
      issued.credential.id,
    );
    if (stored === undefined) throw new Error("credential was not stored");
    expect(stored.secret.digest).toBe(digestOpenPlatformSecret(issued.secret));
    expect(stored.secret.digest).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(stored.secret.reference).toMatch(/^vault:\/\//u);
    expect(JSON.stringify(stored)).not.toContain(issued.secret);

    const rotated = await service.rotateCredential(context, {
      tenantId: "tenant-service",
      credentialId: issued.credential.id,
      idempotencyKey: "credential-rotate-once",
    });
    if (rotated.secret === undefined) throw new Error("rotation secret was not issued");
    expect(rotated.secret).not.toBe(issued.secret);
    expect(rotated.credential.previousCredentialId).toBe(issued.credential.id);
    expect(harness.vault.writeInputs).toHaveLength(2);
    expect(harness.vault.isActive(harness.vault.references[0]!)).toBe(false);

    const revoked = await service.revokeCredential(context, {
      tenantId: "tenant-service",
      credentialId: rotated.credential.id,
      idempotencyKey: "credential-revoke-once",
    });
    expect(revoked.status).toBe("revoked");
    expect(harness.vault.isActive(harness.vault.references[1]!)).toBe(false);
    await expect(service.verifyCredentialSecret(context, {
      tenantId: "tenant-service",
      credentialId: rotated.credential.id,
      secret: rotated.secret,
    })).resolves.toBe(false);
  });

  it("rotates and revokes bindings without retaining plaintext", async () => {
    const { adapter, bindings, vault } = createHarness();
    const issued = await adapter.issueAndBind({
      tenantId: "tenant-secrets",
      subjectType: "application-platform",
      subjectId: "platform-1",
      purpose: "platform-secret",
      gracePeriodSeconds: 60,
    });
    const descriptor = {
      digest: issued.digest,
      reference: issued.reference,
    };

    expect(issued.binding.secretRef).toBe(issued.reference);
    expect(descriptor).toEqual({
      digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
      reference: expect.stringMatching(/^vault:\/\//u),
    });
    expect(JSON.stringify(issued.binding)).not.toContain(issued.secret);
    expect(JSON.stringify(descriptor)).not.toContain(issued.secret);

    vault.failRevokeCount = 1;
    const rotated = await adapter.rotate({
      tenantId: "tenant-secrets",
      subjectType: "application-platform",
      subjectId: "platform-1",
      purpose: "platform-secret",
      gracePeriodSeconds: 60,
      expectedVersion: issued.binding.version,
    });
    expect(rotated.secret).not.toBe(issued.secret);
    expect(rotated.reference).not.toBe(issued.reference);
    expect(rotated.previousBinding.status).toBe("retiring");
    expect(rotated.binding.status).toBe("active");
    expect(vault.writeInputs[1]).toMatchObject({
      previousReference: issued.reference,
      previousGracePeriodSeconds: 60,
      revokePrevious: false,
    });

    const activeReveal = await adapter.reveal({
      tenantId: "tenant-secrets",
      subjectType: "application-platform",
      subjectId: "platform-1",
      purpose: "platform-secret",
    });
    expect(activeReveal).toEqual({
      secret: rotated.secret,
      noStore: true,
      headers: OPEN_PLATFORM_SECRET_NO_STORE_HEADERS,
    });
    expect(vault.isActive(issued.reference)).toBe(false);
    await expect(adapter.reveal({
      tenantId: "tenant-secrets",
      reference: issued.reference,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.CREDENTIAL_UNAVAILABLE,
    });

    const revoked = await adapter.revoke({
      tenantId: "tenant-secrets",
      subjectType: "application-platform",
      subjectId: "platform-1",
      purpose: "platform-secret",
    });
    expect(revoked).toHaveLength(2);
    expect(revoked.every((binding) => binding.status === "revoked")).toBe(true);
    expect(vault.isActive(issued.reference)).toBe(false);
    expect(vault.isActive(rotated.reference)).toBe(false);
    expect((await bindings.list()).items).toHaveLength(2);
    expect(JSON.stringify(adapter)).not.toContain(issued.secret);
    expect(JSON.stringify(adapter)).not.toContain(rotated.secret);
    await expect(adapter.reveal({
      tenantId: "tenant-secrets",
      reference: rotated.reference,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_NOT_FOUND,
    });
  });

  it("isolates tenants and requires explicit reveal authorization", async () => {
    const authorizer = allowReveal();
    const { adapter, vault } = createHarness({
      tenantId: "tenant-a",
      authorizer,
    });
    const issued = await adapter.issueAndBind({
      tenantId: "tenant-a",
      subjectType: "application-client",
      subjectId: "client-a",
      purpose: "oidc-client-secret",
    });

    await expect(adapter.reveal({
      tenantId: "tenant-b",
      reference: issued.reference,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN,
    });
    expect(vault.readCount).toBe(0);

    vi.mocked(authorizer.authorize).mockReturnValue(false);
    await expect(adapter.reveal({
      tenantId: "tenant-a",
      subjectType: "application-client",
      subjectId: "client-a",
      purpose: "oidc-client-secret",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN,
    });
    expect(vault.readCount).toBe(0);

    vi.mocked(authorizer.authorize).mockReturnValue(true);
    const resolver = createIdaasSecretResolver(adapter);
    await expect(resolver(issued.reference)).resolves.toBe(issued.secret);
    expect(authorizer.authorize).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: "tenant-a",
      reference: issued.reference,
      purpose: "oidc-client-secret",
    }));
  });

  it("revalidates tenant, subject, purpose, and reference after subject resolution", async () => {
    const bindings = new ResolvedOverrideSecretBindings({ tenantId: "tenant-a" });
    const { adapter, vault } = createHarness({
      tenantId: "tenant-a",
      bindings,
    });
    const issued = await adapter.issueAndBind({
      tenantId: "tenant-a",
      subjectType: "application-client",
      subjectId: "client-a",
      purpose: "oidc-client-secret",
    });
    const otherReference = "vault://other-tenant-reference-000000000001";
    const base = {
      ...issued.binding,
      tenantId: "tenant-a",
      subjectType: "application-client",
      subjectId: "client-a",
      purpose: "oidc-client-secret",
    } satisfies SecretBindingRecord;
    const request = {
      tenantId: "tenant-a",
      subjectType: "application-client",
      subjectId: "client-a",
      purpose: "oidc-client-secret",
    } as const;

    bindings.resolution = {
      binding: { ...base, tenantId: "tenant-b" },
      usedGracePeriod: false,
    };
    await expect(adapter.reveal(request)).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN,
    });
    bindings.resolution = {
      binding: { ...base, subjectId: "client-b" },
      usedGracePeriod: false,
    };
    await expect(adapter.reveal(request)).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN,
    });
    bindings.resolution = {
      binding: { ...base, purpose: "other-purpose" },
      usedGracePeriod: false,
    };
    await expect(adapter.reveal(request)).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN,
    });
    bindings.resolution = {
      binding: { ...base, secretRef: otherReference },
      usedGracePeriod: false,
    };
    await expect(adapter.reveal({
      ...request,
      reference: issued.reference,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.CREDENTIAL_UNAVAILABLE,
    });
    expect(vault.readCount).toBe(0);
  });

  it("supports provider revoke and compensation lifecycle hooks", async () => {
    const { adapter, vault } = createHarness({ tenantId: "tenant-lifecycle" });
    const issued = await adapter.issue({
      tenantId: "tenant-lifecycle",
      applicationId: "app-lifecycle",
      credentialId: "credential-lifecycle",
      reason: "issue",
    });
    await adapter.revoke({
      tenantId: "tenant-lifecycle",
      applicationId: "app-lifecycle",
      credentialId: "credential-lifecycle",
      digest: issued.digest,
      reference: issued.reference,
      reason: "revocation",
    });
    expect(vault.isActive(issued.reference)).toBe(false);

    const replacement = await adapter.issue({
      tenantId: "tenant-lifecycle",
      applicationId: "app-lifecycle",
      credentialId: "credential-replacement",
      reason: "rotate",
    });
    await adapter.compensate({
      tenantId: "tenant-lifecycle",
      applicationId: "app-lifecycle",
      credentialId: "credential-replacement",
      digest: replacement.digest,
      reference: replacement.reference,
      reason: "issuePersistenceFailed",
    });
    expect(vault.isActive(replacement.reference)).toBe(false);
    expect(vault.revokeInputs.map((input) => input.reason)).toEqual([
      "revoke",
      "compensate",
    ]);
  });

  it("compensates a failed binding write and rejects leaked references safely", async () => {
    const { adapter, vault } = createHarness({ tenantId: "tenant-compensation" });
    await adapter.issueAndBind({
      tenantId: "tenant-compensation",
      subjectType: "application-platform",
      subjectId: "platform-compensation",
      purpose: "platform-secret",
    });
    const failure = await adapter.issueAndBind({
      tenantId: "tenant-compensation",
      subjectType: "application-platform",
      subjectId: "platform-compensation",
      purpose: "platform-secret",
    }).catch((error: unknown) => error);
    expect(failure).toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_CONFLICT,
    });
    const compensatedReference = vault.references[1]!;
    expect(vault.isActive(compensatedReference)).toBe(false);
    expect(vault.revokeInputs.at(-1)).toMatchObject({
      reference: compensatedReference,
      reason: "compensate",
    });
    expect(JSON.stringify(failure)).not.toContain(compensatedReference);

    vault.leakReference = true;
    const leaked = await adapter.issue({
      tenantId: "tenant-compensation",
      applicationId: "app-compensation",
      credentialId: "credential-leaked",
      reason: "issue",
    }).catch((error: unknown) => error);
    expect(leaked).toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.SECRET_ISSUANCE_FAILED,
    });
    const leakedReference = vault.references.at(-1)!;
    const leakedSecret = leakedReference.slice("vault://".length);
    expect(JSON.stringify(leaked)).not.toContain(leakedReference);
    expect(JSON.stringify(leaked)).not.toContain(leakedSecret);
    expect(vault.isActive(leakedReference)).toBe(false);
  });

  it("retries failed external revocations without retaining the reference", async () => {
    const { adapter, vault } = createHarness({ tenantId: "tenant-revoke" });
    const issued = await adapter.issueAndBind({
      tenantId: "tenant-revoke",
      subjectType: "application-platform",
      subjectId: "platform-revoke",
      purpose: "platform-secret",
    });
    vault.failRevokeCount = 2;
    await expect(adapter.revoke({
      tenantId: "tenant-revoke",
      subjectType: "application-platform",
      subjectId: "platform-revoke",
      purpose: "platform-secret",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.CREDENTIAL_UNAVAILABLE,
    });
    await expect(adapter.revoke({
      tenantId: "tenant-revoke",
      subjectType: "application-platform",
      subjectId: "platform-revoke",
      purpose: "platform-secret",
    })).resolves.toHaveLength(1);
    expect(vault.isActive(issued.reference)).toBe(false);
  });

  it("converts resolver failures and logs to safe errors without secret material", async () => {
    const { adapter, vault } = createHarness();
    const issued = await adapter.issueAndBind({
      tenantId: "tenant-secrets",
      subjectType: "application-platform",
      subjectId: "platform-failure",
      purpose: "platform-secret",
    });
    vault.readFailureMessage = `resolver failed for ${issued.secret}`;
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const errorInfo = vi.spyOn(console, "info").mockImplementation(() => undefined);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const resolver = createIdaasSecretResolver(adapter);

    const failure = await resolver(issued.reference).catch((error: unknown) => error);
    expect(failure).toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.CREDENTIAL_UNAVAILABLE,
      message: "Credential is unavailable",
    });
    const serialized = [
      String(failure),
      (failure as Error).message,
      (failure as Error).stack ?? "",
      JSON.stringify(failure),
      JSON.stringify(toOpenPlatformContractError(failure)),
    ].join("\n");
    expect(serialized).not.toContain(issued.secret);
    expect(serialized).not.toContain(issued.reference);
    expect(log).not.toHaveBeenCalled();
    expect(errorInfo).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });

  it("makes production readiness explicit without promoting memory ports", async () => {
    const production = createHarness();
    expect(production.adapter.productionReady).toBe(true);
    expect(production.adapter.readiness).toMatchObject({
      storage: "persistent",
      distributed: true,
    });
    await expect(production.adapter.isProductionReady()).resolves.toBe(true);
    await expect(production.adapter.readinessDetails()).resolves.toEqual({
      ready: true,
      productionReady: true,
      storage: "persistent",
      distributed: true,
      vaultReady: true,
      bindingsReady: true,
    });

    const unavailableVault = new TestSecretVault({ ready: false });
    const development = createHarness({ vault: unavailableVault });
    expect(development.adapter.productionReady).toBe(true);
    await expect(development.adapter.isReady()).resolves.toBe(false);
    await expect(development.adapter.isProductionReady()).resolves.toBe(false);
    await expect(development.adapter.assertProductionReady()).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.CONFIGURATION_ERROR,
    });

    const memoryVault = new TestSecretVault({
      productionReady: false,
      persistent: false,
    });
    const memory = createHarness({ vault: memoryVault });
    expect(memory.adapter.readiness).toMatchObject({
      storage: "memory",
      distributed: false,
    });
    await expect(memory.adapter.isReady()).resolves.toBe(true);
    expect(memory.adapter.productionReady).toBe(false);
  });
});
