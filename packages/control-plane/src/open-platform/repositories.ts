import {
  resourceConflict,
  resourceNotFound,
  validationError,
} from "./errors.js";
import { InMemoryIdempotencyStore } from "./idempotency.js";
import {
  InMemoryOpenPlatformAuditEventStore,
  type InMemoryOpenPlatformAuditStoreOptions,
} from "./audit.js";
import {
  InMemoryOpenPlatformWebhookDeliveryRepository,
  InMemoryOpenPlatformWebhookRepository,
  type OpenPlatformWebhookDelivery,
  type OpenPlatformWebhookPort,
} from "./webhook.js";
import {
  assertCredentialStatus,
  assertCredentialTransition,
} from "./state-machine.js";
import type {
  ApiProduct,
  ApiProductRepository,
  ApiVersion,
  ApiVersionRepository,
  Application,
  ApplicationEnvironment,
  ApplicationEnvironmentRepository,
  ApplicationRepository,
  CredentialRecord,
  CredentialRepository,
  DeveloperOrganization,
  DeveloperOrganizationRepository,
  OpenPlatformDependencyReadiness,
  OpenPlatformEntityKind,
  OpenPlatformRecord,
  OpenPlatformRepositories,
  ScopeGrant,
  ScopeGrantRepository,
  Subscription,
  SubscriptionRepository,
  Tenant,
  TenantRepository,
  TenantScopedRepository,
  UsageRecord,
  UsageRepository,
} from "./types.js";
import {
  normalizeResourceId,
  normalizeTenantKey,
} from "./validation.js";

export class InMemoryTenantScopedRepository<
  T extends OpenPlatformRecord,
> implements TenantScopedRepository<T> {
  protected readonly records = new Map<string, T>();
  private readonly expectedKind: OpenPlatformEntityKind;

  constructor(expectedKind: OpenPlatformEntityKind) {
    this.expectedKind = expectedKind;
  }

  async create(record: T): Promise<T> {
    validateRecordIdentity(record, this.expectedKind);
    if (this.records.has(record.id)) {
      throw resourceConflict("Open platform resource identifier already exists");
    }
    const stored = this.cloneRecord(record);
    this.records.set(stored.id, stored);
    return this.cloneRecord(stored);
  }

  async get(tenantId: string, id: string): Promise<T | undefined> {
    const normalizedTenantId = normalizeTenantKey(tenantId);
    const normalizedId = normalizeResourceId(id, this.expectedKind);
    const record = this.records.get(normalizedId);
    if (record === undefined || record.tenantId !== normalizedTenantId) {
      return undefined;
    }
    return this.cloneRecord(record);
  }

  async list(tenantId: string): Promise<T[]> {
    const normalizedTenantId = normalizeTenantKey(tenantId);
    return [...this.records.values()]
      .filter((record) => record.tenantId === normalizedTenantId)
      .sort(compareRecords)
      .map((record) => this.cloneRecord(record));
  }

  async save(record: T): Promise<T> {
    validateRecordIdentity(record, this.expectedKind);
    const current = this.records.get(record.id);
    if (current === undefined || current.tenantId !== record.tenantId) {
      throw resourceNotFound(this.expectedKind);
    }
    if (record.version !== current.version + 1) {
      throw resourceConflict("Open platform resource version is stale");
    }
    if (
      record.kind !== current.kind ||
      record.createdAt !== current.createdAt
    ) {
      throw resourceConflict("Open platform resource identity is immutable");
    }
    const stored = this.cloneRecord(record);
    this.records.set(stored.id, stored);
    return this.cloneRecord(stored);
  }

  snapshot(tenantId: string): T[] {
    const normalizedTenantId = normalizeTenantKey(tenantId);
    return [...this.records.values()]
      .filter((record) => record.tenantId === normalizedTenantId)
      .sort(compareRecords)
      .map((record) => this.cloneRecord(record));
  }

  protected cloneRecord(record: T): T {
    return structuredClone(record);
  }
}

export class InMemoryTenantRepository
  extends InMemoryTenantScopedRepository<Tenant>
  implements TenantRepository {
  constructor() {
    super("tenant");
  }

  override async create(record: Tenant): Promise<Tenant> {
    if ([...this.records.values()].some(
      (existing) => existing.tenantId === record.tenantId,
    )) {
      throw resourceConflict("Open platform tenant already exists");
    }
    return super.create(record);
  }

  async getByTenantId(tenantId: string): Promise<Tenant | undefined> {
    const normalizedTenantId = normalizeTenantKey(tenantId);
    return (await this.list(normalizedTenantId)).find(
      (record) => record.tenantId === normalizedTenantId,
    );
  }
}

export class InMemoryDeveloperOrganizationRepository
  extends InMemoryTenantScopedRepository<DeveloperOrganization>
  implements DeveloperOrganizationRepository {
  constructor() {
    super("developerOrganization");
  }
}

export class InMemoryApplicationRepository
  extends InMemoryTenantScopedRepository<Application>
  implements ApplicationRepository {
  constructor() {
    super("application");
  }
}

export class InMemoryApplicationEnvironmentRepository
  extends InMemoryTenantScopedRepository<ApplicationEnvironment>
  implements ApplicationEnvironmentRepository {
  constructor() {
    super("applicationEnvironment");
  }
}

export class InMemoryApiProductRepository
  extends InMemoryTenantScopedRepository<ApiProduct>
  implements ApiProductRepository {
  constructor() {
    super("apiProduct");
  }
}

export class InMemoryApiVersionRepository
  extends InMemoryTenantScopedRepository<ApiVersion>
  implements ApiVersionRepository {
  constructor() {
    super("apiVersion");
  }
}

export class InMemoryCredentialRepository
  extends InMemoryTenantScopedRepository<CredentialRecord>
  implements CredentialRepository {
  constructor() {
    super("credential");
  }

  override async create(record: CredentialRecord): Promise<CredentialRecord> {
    return super.create(this.sanitizeCredential(record));
  }

  override async save(record: CredentialRecord): Promise<CredentialRecord> {
    const sanitized = this.sanitizeCredential(record);
    const current = this.records.get(sanitized.id);
    if (current === undefined || current.tenantId !== sanitized.tenantId) {
      throw resourceNotFound("credential");
    }
    if (
      current.createdAt !== sanitized.createdAt ||
      current.applicationId !== sanitized.applicationId ||
      current.environmentId !== sanitized.environmentId ||
      current.name !== sanitized.name ||
      current.expiresAt !== sanitized.expiresAt ||
      current.fingerprint !== sanitized.fingerprint ||
      current.secret.digest !== sanitized.secret.digest ||
      current.secret.reference !== sanitized.secret.reference ||
      current.previousCredentialId !== sanitized.previousCredentialId ||
      !sameStringArray(current.scopes, sanitized.scopes)
    ) {
      throw resourceConflict("Credential identity and secret are immutable");
    }
    assertCredentialTransition(current.status, sanitized.status);
    return super.save(sanitized);
  }

  async rotate(
    previousCredential: CredentialRecord,
    replacementCredential: CredentialRecord,
  ): Promise<{
    credential: CredentialRecord;
    previousCredential: CredentialRecord;
  }> {
    const previous = this.sanitizeCredential(previousCredential);
    const replacement = this.sanitizeCredential(replacementCredential);
    const current = this.records.get(previous.id);
    if (current === undefined || current.tenantId !== previous.tenantId) {
      throw resourceNotFound("credential");
    }
    if (
      current.status !== "active" ||
      current.version !== previous.version - 1 ||
      previous.status !== "rotated" ||
      previous.replacedByCredentialId !== replacement.id ||
      replacement.previousCredentialId !== previous.id ||
      replacement.status !== "active" ||
      replacement.version !== 1 ||
      current.tenantId !== replacement.tenantId ||
      current.applicationId !== replacement.applicationId ||
      current.environmentId !== replacement.environmentId ||
      current.name !== previous.name ||
      current.name !== replacement.name ||
      !sameStringArray(current.scopes, previous.scopes) ||
      !sameStringArray(current.scopes, replacement.scopes) ||
      current.expiresAt !== previous.expiresAt ||
      current.expiresAt !== replacement.expiresAt ||
      current.secret.digest !== previous.secret.digest ||
      current.secret.reference !== previous.secret.reference ||
      current.fingerprint !== previous.fingerprint ||
      current.secret.digest === replacement.secret.digest
    ) {
      throw resourceConflict("Credential rotation is inconsistent");
    }
    if (this.records.has(replacement.id)) {
      throw resourceConflict("Credential identifier already exists");
    }
    this.records.set(previous.id, previous);
    this.records.set(replacement.id, replacement);
    return {
      credential: this.cloneRecord(replacement),
      previousCredential: this.cloneRecord(previous),
    };
  }

  protected override cloneRecord(record: CredentialRecord): CredentialRecord {
    return this.sanitizeCredential(record);
  }

  private sanitizeCredential(record: CredentialRecord): CredentialRecord {
    validateRecordIdentity(record, "credential");
    assertCredentialStatus(record.status);
    if (
      !Number.isSafeInteger(record.version) ||
      record.version < 1 ||
      !Array.isArray(record.scopes) ||
      record.scopes.length === 0 ||
      record.scopes.some((scope) => typeof scope !== "string")
    ) {
      throw validationError("Credential record is invalid");
    }
    if (
      typeof record.secret !== "object" ||
      record.secret === null ||
      !isDigest(record.secret.digest)
    ) {
      throw validationError("Credential secret digest is invalid");
    }
    return {
      id: record.id,
      tenantId: record.tenantId,
      kind: "credential",
      version: record.version,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      applicationId: normalizeResourceId(record.applicationId, "application"),
      ...(record.environmentId === undefined
        ? {}
        : {
            environmentId: normalizeResourceId(
              record.environmentId,
              "applicationEnvironment",
            ),
          }),
      name: requireText(record.name, 200),
      status: record.status,
      scopes: [...record.scopes],
      secret: {
        digest: record.secret.digest,
        ...(record.secret.reference === undefined
          ? {}
          : { reference: normalizeReference(record.secret.reference) }),
      },
      fingerprint: requireText(record.fingerprint, 256),
      ...(record.expiresAt === undefined
        ? {}
        : { expiresAt: record.expiresAt }),
      ...(record.rotatedAt === undefined
        ? {}
        : { rotatedAt: record.rotatedAt }),
      ...(record.revokedAt === undefined
        ? {}
        : { revokedAt: record.revokedAt }),
      ...(record.replacedByCredentialId === undefined
        ? {}
        : {
            replacedByCredentialId: normalizeResourceId(
              record.replacedByCredentialId,
              "credential",
            ),
          }),
      ...(record.previousCredentialId === undefined
        ? {}
        : {
            previousCredentialId: normalizeResourceId(
              record.previousCredentialId,
              "credential",
            ),
          }),
    };
  }
}

export class InMemorySubscriptionRepository
  extends InMemoryTenantScopedRepository<Subscription>
  implements SubscriptionRepository {
  constructor() {
    super("subscription");
  }
}

export class InMemoryScopeGrantRepository
  extends InMemoryTenantScopedRepository<ScopeGrant>
  implements ScopeGrantRepository {
  constructor() {
    super("scopeGrant");
  }

  async revoke(
    tenantId: string,
    id: string,
    revokedAt: string,
  ): Promise<ScopeGrant> {
    const current = await this.get(tenantId, id);
    if (current === undefined) throw resourceNotFound("scopeGrant");
    if (current.status !== "active" || current.revokedAt !== undefined) {
      throw resourceConflict("Scope grant is already revoked");
    }
    return this.save({
      ...current,
      status: "revoked",
      version: current.version + 1,
      revokedAt,
      updatedAt: revokedAt,
    });
  }
}

export class InMemoryUsageRepository implements UsageRepository {
  private readonly records = new Map<string, UsageRecord>();

  async append(record: UsageRecord): Promise<UsageRecord> {
    validateRecordIdentity(record, "usage");
    if (record.version !== 1) {
      throw validationError("Usage record version is invalid");
    }
    if (this.records.has(record.id)) {
      throw resourceConflict("Usage record already exists");
    }
    const stored = structuredClone(record);
    this.records.set(stored.id, stored);
    return structuredClone(stored);
  }

  async get(tenantId: string, id: string): Promise<UsageRecord | undefined> {
    const normalizedTenantId = normalizeTenantKey(tenantId);
    const normalizedId = normalizeResourceId(id, "usage");
    const record = this.records.get(normalizedId);
    return record === undefined || record.tenantId !== normalizedTenantId
      ? undefined
      : structuredClone(record);
  }

  async list(tenantId: string): Promise<UsageRecord[]> {
    const normalizedTenantId = normalizeTenantKey(tenantId);
    return [...this.records.values()]
      .filter((record) => record.tenantId === normalizedTenantId)
      .sort(compareRecords)
      .map((record) => structuredClone(record));
  }

  snapshot(tenantId: string): UsageRecord[] {
    return [...this.records.values()]
      .filter((record) => record.tenantId === normalizeTenantKey(tenantId))
      .sort(compareRecords)
      .map((record) => structuredClone(record));
  }
}

export interface InMemoryOpenPlatformRepositoriesOptions {
  clock?: () => Date;
  production?: boolean;
  idempotencyLeaseMs?: number;
  idempotencyRetentionMs?: number;
}

export class InMemoryOpenPlatformRepositories
  implements OpenPlatformRepositories {
  readonly readiness: OpenPlatformDependencyReadiness;
  readonly tenants = new InMemoryTenantRepository();
  readonly developerOrganizations =
    new InMemoryDeveloperOrganizationRepository();
  readonly applications = new InMemoryApplicationRepository();
  readonly applicationEnvironments =
    new InMemoryApplicationEnvironmentRepository();
  readonly apiProducts = new InMemoryApiProductRepository();
  readonly apiVersions = new InMemoryApiVersionRepository();
  readonly credentials = new InMemoryCredentialRepository();
  readonly subscriptions = new InMemorySubscriptionRepository();
  readonly scopeGrants = new InMemoryScopeGrantRepository();
  readonly usage = new InMemoryUsageRepository();
  readonly idempotency: InMemoryIdempotencyStore;
  readonly auditEvents: InMemoryOpenPlatformAuditEventStore;
  readonly webhooks: InMemoryOpenPlatformWebhookRepository;
  readonly webhookDeliveries: InMemoryOpenPlatformWebhookDeliveryRepository;

  constructor(options: InMemoryOpenPlatformRepositoriesOptions = {}) {
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.production !== true,
    });
    this.idempotency = new InMemoryIdempotencyStore({
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      ...(options.idempotencyLeaseMs === undefined
        ? {}
        : { leaseMs: options.idempotencyLeaseMs }),
      ...(options.idempotencyRetentionMs === undefined
        ? {}
        : { retentionMs: options.idempotencyRetentionMs }),
    });
    this.auditEvents = new InMemoryOpenPlatformAuditEventStore({
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      production: options.production,
    });
    this.webhooks = new InMemoryOpenPlatformWebhookRepository();
    this.webhookDeliveries = new InMemoryOpenPlatformWebhookDeliveryRepository();
  }

  async isReady(): Promise<boolean> {
    return this.readiness.ready();
  }
}

export function createInMemoryOpenPlatformRepositories(
  options: InMemoryOpenPlatformRepositoriesOptions = {},
): InMemoryOpenPlatformRepositories {
  return new InMemoryOpenPlatformRepositories(options);
}

function validateRecordIdentity(
  record: OpenPlatformRecord,
  expectedKind: OpenPlatformEntityKind,
): void {
  if (record === null || typeof record !== "object") {
    throw validationError("Open platform record is invalid");
  }
  const normalizedId = normalizeResourceId(record.id, expectedKind);
  const normalizedTenantId = normalizeTenantKey(record.tenantId);
  if (record.id !== normalizedId || record.tenantId !== normalizedTenantId) {
    throw validationError("Open platform record identifier is not canonical");
  }
  if (record.kind !== expectedKind) {
    throw validationError("Open platform record kind is invalid");
  }
}

function requireText(value: unknown, maxLength: number): string {
  if (typeof value !== "string") {
    throw validationError("Open platform record text is invalid");
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > maxLength ||
    /[\u0000-\u000f\u007f]/u.test(normalized)
  ) {
    throw validationError("Open platform record text is invalid");
  }
  return normalized;
}

function normalizeReference(value: unknown): string {
  if (typeof value !== "string") {
    throw validationError("Credential secret reference is invalid");
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 2048 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw validationError("Credential secret reference is invalid");
  }
  return normalized;
}

function sameStringArray(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index]);
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function compareRecords(
  left: OpenPlatformRecord,
  right: OpenPlatformRecord,
): number {
  const created = left.createdAt.localeCompare(right.createdAt);
  return created === 0 ? left.id.localeCompare(right.id) : created;
}
