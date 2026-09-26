import {
  assertCredentialTransition,
  assertLifecycleTransition,
} from "../state-machine.js";
import {
  resourceConflict,
  resourceNotFound,
  validationError,
} from "../errors.js";
import type {
  ApiProduct,
  ApiVersion,
  Application,
  ApplicationEnvironment,
  CredentialRecord,
  CredentialRepository,
  DeveloperOrganization,
  OpenPlatformLifecycleRecord,
  ScopeGrant,
  ScopeGrantRepository,
  Subscription,
  Tenant,
  TenantRepository,
  UsageRecord,
  UsageRepository,
} from "../types.js";
import {
  OpenPlatformSqlRepository,
  OpenPlatformSqlRuntime,
  createOpenPlatformSqlRuntime,
  createEtag,
  normalizeStorageId,
  normalizeTenant,
  readDate,
  readDecimalQuantity,
  readEtag,
  readNumber,
  readStringArray,
  readText,
  rowValue,
  storageValue,
  withEtag,
  type OpenPlatformSqlRecord,
  type OpenPlatformSqlRepositoryInput,
  type OpenPlatformSqlRepositorySecondOptions,
} from "./adapter.js";

abstract class SqlLifecycleRepository<T extends OpenPlatformLifecycleRecord>
  extends OpenPlatformSqlRepository<T> {
  protected validateTransition(current: T, next: T): void {
    if (current.status !== next.status) {
      assertLifecycleTransition(current.status, next.status);
    }
  }

  protected mapLifecycleRow(
    row: Record<string, unknown>,
    kind: T["kind"],
  ): OpenPlatformSqlRecord<T> {
    const id = requiredText(rowValue(row, "id"), kind);
    const tenantId = requiredText(rowValue(row, "tenantId"), kind);
    const status = requiredText(rowValue(row, "status"), kind);
    const createdAt = requiredDate(rowValue(row, "createdAt"), kind);
    const updatedAt = requiredDate(rowValue(row, "updatedAt"), kind);
    const version = requiredVersion(rowValue(row, "version"), kind);
    const record = {
      id,
      tenantId,
      kind,
      status,
      version,
      createdAt,
      updatedAt,
      ...(readDate(rowValue(row, "archivedAt")) === undefined
        ? {}
        : { archivedAt: readDate(rowValue(row, "archivedAt")) }),
    } as unknown as T;
    return withEtag(record, readEtag(row) ?? createEtag(kind, id, version));
  }
}

export class SqlTenantRepository
  extends SqlLifecycleRepository<Tenant>
  implements TenantRepository {
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    super(createOpenPlatformSqlRuntime(input, options), "tenants", "tenant");
  }

  async getByTenantId(tenantId: string): Promise<OpenPlatformSqlRecord<Tenant> | undefined> {
    const tenant = normalizeTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("tenants", values, clauses, tenant);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("tenants")} FROM ${this.runtime.table("tenants")} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows.length === 0) return undefined;
    const record = this.mapRow(rows[0]);
    return record.tenantId === this.runtime.tenantId ? record : undefined;
  }

  protected override mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<Tenant> {
    const record = this.mapLifecycleRow(row, "tenant");
    const name = requiredText(rowValue(row, "name"), "tenant");
    return withEtag({ ...record, name }, readEtag(row) ?? record.etag);
  }
}

export class SqlDeveloperOrganizationRepository
  extends SqlLifecycleRepository<DeveloperOrganization> {
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    super(createOpenPlatformSqlRuntime(input, options), "developerOrganizations", "developerOrganization");
  }

  protected override mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<DeveloperOrganization> {
    const record = this.mapLifecycleRow(row, "developerOrganization");
    const name = requiredText(rowValue(row, "name"), "developerOrganization");
    const description = readText(rowValue(row, "description"));
    return withEtag(
      { ...record, name, ...(description === undefined ? {} : { description }) },
      readEtag(row) ?? record.etag,
    );
  }
}

export class SqlApplicationRepository
  extends SqlLifecycleRepository<Application> {
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    super(createOpenPlatformSqlRuntime(input, options), "applications", "application");
  }

  protected override mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<Application> {
    const record = this.mapLifecycleRow(row, "application");
    const organizationId = requiredText(rowValue(row, "organizationId"), "application");
    const name = requiredText(rowValue(row, "name"), "application");
    const description = readText(rowValue(row, "description"));
    return withEtag(
      { ...record, organizationId, name, ...(description === undefined ? {} : { description }) },
      readEtag(row) ?? record.etag,
    );
  }
}

export class SqlApplicationEnvironmentRepository
  extends SqlLifecycleRepository<ApplicationEnvironment> {
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    super(createOpenPlatformSqlRuntime(input, options), "applicationEnvironments", "applicationEnvironment");
  }

  protected override mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<ApplicationEnvironment> {
    const record = this.mapLifecycleRow(row, "applicationEnvironment");
    const applicationId = requiredText(rowValue(row, "applicationId"), "applicationEnvironment");
    const name = requiredText(rowValue(row, "name"), "applicationEnvironment");
    return withEtag({ ...record, applicationId, name }, readEtag(row) ?? record.etag);
  }
}

export class SqlApiProductRepository
  extends SqlLifecycleRepository<ApiProduct> {
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    super(createOpenPlatformSqlRuntime(input, options), "apiProducts", "apiProduct");
  }

  protected override mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<ApiProduct> {
    const record = this.mapLifecycleRow(row, "apiProduct");
    const name = requiredText(rowValue(row, "name"), "apiProduct");
    const description = readText(rowValue(row, "description"));
    return withEtag(
      { ...record, name, ...(description === undefined ? {} : { description }), scopes: readStringArray(rowValue(row, "scopes")) },
      readEtag(row) ?? record.etag,
    );
  }
}

export class SqlApiVersionRepository
  extends SqlLifecycleRepository<ApiVersion> {
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    super(createOpenPlatformSqlRuntime(input, options), "apiVersions", "apiVersion");
  }

  protected override mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<ApiVersion> {
    const record = this.mapLifecycleRow(row, "apiVersion");
    const productId = requiredText(rowValue(row, "productId"), "apiVersion");
    const apiVersion = requiredText(rowValue(row, "apiVersion"), "apiVersion");
    const description = readText(rowValue(row, "description"));
    return withEtag(
      {
        ...record,
        productId,
        apiVersion,
        ...(description === undefined ? {} : { description }),
        scopes: readStringArray(rowValue(row, "scopes")),
      },
      readEtag(row) ?? record.etag,
    );
  }
}

export class SqlSubscriptionRepository
  extends SqlLifecycleRepository<Subscription> {
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    super(createOpenPlatformSqlRuntime(input, options), "subscriptions", "subscription");
  }

  protected override mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<Subscription> {
    const record = this.mapLifecycleRow(row, "subscription");
    const applicationId = requiredText(rowValue(row, "applicationId"), "subscription");
    const productId = requiredText(rowValue(row, "productId"), "subscription");
    const apiVersionId = readText(rowValue(row, "apiVersionId"));
    const name = requiredText(rowValue(row, "name"), "subscription");
    return withEtag(
      {
        ...record,
        applicationId,
        productId,
        ...(apiVersionId === undefined ? {} : { apiVersionId }),
        name,
        scopes: readStringArray(rowValue(row, "scopes")),
      },
      readEtag(row) ?? record.etag,
    );
  }
}

export class SqlCredentialRepository
  extends OpenPlatformSqlRepository<CredentialRecord>
  implements CredentialRepository {
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    super(createOpenPlatformSqlRuntime(input, options), "credentials", "credential");
  }

  protected override prepareCreate(record: CredentialRecord): CredentialRecord {
    return sanitizeCredential(super.prepareCreate(record));
  }

  protected override prepareSave(record: CredentialRecord): CredentialRecord {
    return sanitizeCredential(super.prepareSave(record));
  }

  protected override validateIdentity(record: CredentialRecord): void {
    super.validateIdentity(record);
    normalizeStorageId(record.applicationId);
    if (record.environmentId !== undefined) normalizeStorageId(record.environmentId);
    if (record.previousCredentialId !== undefined) normalizeStorageId(record.previousCredentialId);
    if (record.replacedByCredentialId !== undefined) normalizeStorageId(record.replacedByCredentialId);
  }

  protected override validateTransition(current: CredentialRecord, next: CredentialRecord): void {
    if (current.status !== next.status) {
      assertCredentialTransition(current.status, next.status);
    }
    if (
      current.applicationId !== next.applicationId ||
      current.environmentId !== next.environmentId ||
      current.name !== next.name ||
      current.fingerprint !== next.fingerprint ||
      current.secret.digest !== next.secret.digest ||
      current.secret.reference !== next.secret.reference ||
      current.expiresAt !== next.expiresAt ||
      current.previousCredentialId !== next.previousCredentialId ||
      !sameStringArray(current.scopes, next.scopes)
    ) {
      throw resourceConflict("Credential identity and secret are immutable");
    }
  }

  protected override insertValues(record: CredentialRecord): unknown[] {
    const normalized = sanitizeCredential(record);
    return [
      normalized.id,
      normalized.tenantId,
      normalized.kind,
      normalized.applicationId,
      normalized.environmentId,
      normalized.name,
      normalized.status,
      storageValue("scopes", normalized.scopes),
      normalized.secret.digest,
      normalized.secret.reference,
      normalized.fingerprint,
      normalized.expiresAt,
      normalized.rotatedAt,
      normalized.revokedAt,
      normalized.replacedByCredentialId,
      normalized.previousCredentialId,
      normalized.version,
      createEtag("credential", normalized.id, normalized.version),
      normalized.createdAt,
      normalized.updatedAt,
    ];
  }

  protected override mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<CredentialRecord> {
    const id = requiredText(rowValue(row, "id"), "credential");
    const tenantId = requiredText(rowValue(row, "tenantId"), "credential");
    const applicationId = requiredText(rowValue(row, "applicationId"), "credential");
    const environmentId = readText(rowValue(row, "environmentId"));
    const name = requiredText(rowValue(row, "name"), "credential");
    const status = requiredText(rowValue(row, "status"), "credential");
    const secretDigest = requiredText(rowValue(row, "secretDigest"), "credential");
    const secretReference = readText(rowValue(row, "secretReference"));
    const fingerprint = requiredText(rowValue(row, "fingerprint"), "credential");
    const createdAt = requiredDate(rowValue(row, "createdAt"), "credential");
    const updatedAt = requiredDate(rowValue(row, "updatedAt"), "credential");
    const version = requiredVersion(rowValue(row, "version"), "credential");
    const record: CredentialRecord = {
      id,
      tenantId,
      kind: "credential",
      applicationId,
      ...(environmentId === undefined ? {} : { environmentId }),
      name,
      status: status as CredentialRecord["status"],
      scopes: readStringArray(rowValue(row, "scopes")),
      secret: {
        digest: secretDigest,
        ...(secretReference === undefined ? {} : { reference: secretReference }),
      },
      fingerprint,
      ...optionalDateField("expiresAt", rowValue(row, "expiresAt")),
      ...optionalDateField("rotatedAt", rowValue(row, "rotatedAt")),
      ...optionalDateField("revokedAt", rowValue(row, "revokedAt")),
      ...optionalTextField("replacedByCredentialId", rowValue(row, "replacedByCredentialId")),
      ...optionalTextField("previousCredentialId", rowValue(row, "previousCredentialId")),
      version,
      createdAt,
      updatedAt,
    };
    return withEtag(record, readEtag(row) ?? createEtag("credential", id, version));
  }

  async rotate(
    previousCredential: CredentialRecord,
    replacementCredential: CredentialRecord,
  ): Promise<{
    credential: OpenPlatformSqlRecord<CredentialRecord>;
    previousCredential: OpenPlatformSqlRecord<CredentialRecord>;
  }> {
    const previous = sanitizeCredential(previousCredential);
    const replacement = sanitizeCredential(replacementCredential);
    return this.runtime.withTransaction(async (executor) => {
      const current = await this.requireCurrent(previous.tenantId, previous.id, executor);
      if (
        current.status !== "active" ||
        previous.status !== "rotated" ||
        replacement.status !== "active" ||
        previous.version !== current.version + 1 ||
        replacement.version !== 1 ||
        previous.replacedByCredentialId !== replacement.id ||
        replacement.previousCredentialId !== previous.id ||
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
      const updatedPrevious = await this.updateValues(previous, current, executor);
      if (updatedPrevious.affected !== 1) {
        throw resourceConflict("Credential version is stale");
      }
      const inserted = await super.create(replacement);
      return {
        credential: inserted,
        previousCredential: updatedPrevious.rows[0] === undefined
          ? withEtag(previous, createEtag("credential", previous.id, previous.version))
          : this.mapRow(updatedPrevious.rows[0]),
      };
    });
  }

  async revoke(tenantId: string, id: string, revokedAt: string): Promise<OpenPlatformSqlRecord<CredentialRecord>> {
    const tenant = normalizeTenant(tenantId);
    const current = await this.requireCurrent(tenant, normalizeStorageId(id));
    if (current.status !== "active") throw resourceConflict("Credential is already unavailable");
    return this.save({
      ...current,
      status: "revoked",
      version: current.version + 1,
      revokedAt,
      updatedAt: revokedAt,
    });
  }
}

export class SqlScopeGrantRepository
  extends OpenPlatformSqlRepository<ScopeGrant>
  implements ScopeGrantRepository {
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    super(createOpenPlatformSqlRuntime(input, options), "scopeGrants", "scopeGrant");
  }

  protected override validateTransition(current: ScopeGrant, next: ScopeGrant): void {
    if (current.status === "active" && next.status === "revoked") return;
    if (current.status === next.status) return;
    throw resourceConflict("Scope grant state changed");
  }

  protected override insertValues(record: ScopeGrant): unknown[] {
    return [
      record.id,
      record.tenantId,
      record.kind,
      record.credentialId,
      record.applicationId,
      record.productId,
      record.apiVersionId,
      storageValue("scopes", record.scopes),
      record.status,
      record.grantedAt,
      record.revokedAt,
      record.version,
      createEtag("scopeGrant", record.id, record.version),
      record.createdAt,
      record.updatedAt,
    ];
  }

  protected override mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<ScopeGrant> {
    const id = requiredText(rowValue(row, "id"), "scopeGrant");
    const tenantId = requiredText(rowValue(row, "tenantId"), "scopeGrant");
    const credentialId = requiredText(rowValue(row, "credentialId"), "scopeGrant");
    const applicationId = requiredText(rowValue(row, "applicationId"), "scopeGrant");
    const productId = requiredText(rowValue(row, "productId"), "scopeGrant");
    const apiVersionId = readText(rowValue(row, "apiVersionId"));
    const status = requiredText(rowValue(row, "status"), "scopeGrant");
    const grantedAt = requiredDate(rowValue(row, "grantedAt"), "scopeGrant");
    const version = requiredVersion(rowValue(row, "version"), "scopeGrant");
    const record: ScopeGrant = {
      id,
      tenantId,
      kind: "scopeGrant",
      credentialId,
      applicationId,
      productId,
      ...(apiVersionId === undefined ? {} : { apiVersionId }),
      scopes: readStringArray(rowValue(row, "scopes")),
      status: status as ScopeGrant["status"],
      grantedAt,
      ...optionalDateField("revokedAt", rowValue(row, "revokedAt")),
      version,
      createdAt: requiredDate(rowValue(row, "createdAt"), "scopeGrant"),
      updatedAt: requiredDate(rowValue(row, "updatedAt"), "scopeGrant"),
    };
    return withEtag(record, readEtag(row) ?? createEtag("scopeGrant", id, version));
  }

  async revoke(
    tenantId: string,
    id: string,
    revokedAt: string,
  ): Promise<OpenPlatformSqlRecord<ScopeGrant>> {
    const tenant = normalizeTenant(tenantId);
    const current = await this.requireCurrent(tenant, normalizeStorageId(id));
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

export class SqlUsageRepository implements UsageRepository {
  private readonly runtime: OpenPlatformSqlRuntime;

  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    this.runtime = createOpenPlatformSqlRuntime(input, options);
  }

  async append(record: UsageRecord): Promise<OpenPlatformSqlRecord<UsageRecord>> {
    const normalized = normalizeUsage(record, this.runtime.tenantId);
    return this.runtime.withTransaction(async (executor) => {
      const fields = [
        "id",
        "tenantId",
        "kind",
        "subscriptionId",
        "credentialId",
        "productId",
        "apiVersionId",
        "metric",
        "quantity",
        "occurredAt",
        "idempotencyKey",
        "version",
        "etag",
        "createdAt",
        "updatedAt",
      ];
      const values = [
        normalized.id,
        normalized.tenantId,
        normalized.kind,
        normalized.subscriptionId,
        normalized.credentialId,
        normalized.productId,
        normalized.apiVersionId,
        normalized.metric,
        normalized.quantity,
        normalized.occurredAt,
        normalized.idempotencyKey,
        normalized.version,
        createEtag("usage", normalized.id, normalized.version),
        normalized.createdAt,
        normalized.updatedAt,
      ];
      const result = await this.runtime.executeMutation(
        `INSERT INTO ${this.runtime.table("usage")} (${fields.map((field) => this.runtime.column("usage", field)).join(", ")}) VALUES (${fields.map((_field, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.runtime.select("usage", fields)}`,
        values,
        executor,
      );
      if (result.affected !== 1) throw resourceConflict("Usage record already exists");
      return result.rows[0] === undefined
        ? withEtag(normalized, createEtag("usage", normalized.id, normalized.version))
        : this.mapRow(result.rows[0]);
    });
  }

  async get(tenantId: string, id: string): Promise<OpenPlatformSqlRecord<UsageRecord> | undefined> {
    const tenant = normalizeTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("usage", values, clauses, tenant);
    values.push(normalizeStorageId(id));
    clauses.push(`${this.runtime.column("usage", "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("usage")} FROM ${this.runtime.table("usage")} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows.length === 0) return undefined;
    const record = this.mapRow(rows[0]);
    return record.tenantId === this.runtime.tenantId ? record : undefined;
  }

  async list(tenantId: string): Promise<OpenPlatformSqlRecord<UsageRecord>[]> {
    const tenant = normalizeTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("usage", values, clauses, tenant);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("usage")} FROM ${this.runtime.table("usage")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("usage", "occurredAt")} ASC, ${this.runtime.column("usage", "id")} ASC`,
      values,
    );
    return rows.map((row) => this.mapRow(row)).filter((record) => record.tenantId === this.runtime.tenantId);
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["usage"]);
  }

  private mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<UsageRecord> {
    const id = requiredText(rowValue(row, "id"), "usage");
    const tenantId = requiredText(rowValue(row, "tenantId"), "usage");
    const subscriptionId = requiredText(rowValue(row, "subscriptionId"), "usage");
    const productId = requiredText(rowValue(row, "productId"), "usage");
    const apiVersionId = readText(rowValue(row, "apiVersionId"));
    const metric = requiredText(rowValue(row, "metric"), "usage");
    const quantity = requiredQuantity(rowValue(row, "quantity"), "usage");
    const occurredAt = requiredDate(rowValue(row, "occurredAt"), "usage");
    const idempotencyKey = requiredText(rowValue(row, "idempotencyKey"), "usage");
    const version = requiredVersion(rowValue(row, "version"), "usage");
    const record: UsageRecord = {
      id,
      tenantId,
      kind: "usage",
      subscriptionId,
      ...optionalTextField("credentialId", rowValue(row, "credentialId")),
      productId,
      ...(apiVersionId === undefined ? {} : { apiVersionId }),
      metric,
      quantity,
      occurredAt,
      idempotencyKey,
      version,
      createdAt: requiredDate(rowValue(row, "createdAt"), "usage"),
      updatedAt: requiredDate(rowValue(row, "updatedAt"), "usage"),
    };
    return withEtag(record, readEtag(row) ?? createEtag("usage", id, version));
  }
}

function sanitizeCredential(record: CredentialRecord): CredentialRecord {
  if (record === null || typeof record !== "object") {
    throw validationError("Credential record is invalid");
  }
  if (record.kind !== "credential" || !Array.isArray(record.scopes) || record.scopes.length === 0) {
    throw validationError("Credential record is invalid");
  }
  if (record.secret === null || typeof record.secret !== "object") {
    throw validationError("Credential secret storage is invalid");
  }
  const secretKeys = Object.keys(record.secret);
  if (secretKeys.some((key) => key !== "digest" && key !== "reference")) {
    throw validationError("Credential secret storage is invalid");
  }
  if (!isDigest(record.secret.digest)) {
    throw validationError("Credential secret digest is invalid");
  }
  const reference = record.secret.reference;
  if (reference !== undefined && (typeof reference !== "string" || reference.trim().length < 1 || reference.length > 2048 || /\s/u.test(reference))) {
    throw validationError("Credential secret reference is invalid");
  }
  return {
    id: normalizeStorageId(record.id),
    tenantId: normalizeTenant(record.tenantId),
    kind: "credential",
    version: record.version,
    createdAt: requiredDate(record.createdAt, "credential"),
    updatedAt: requiredDate(record.updatedAt, "credential"),
    applicationId: normalizeStorageId(record.applicationId),
    ...(record.environmentId === undefined ? {} : { environmentId: normalizeStorageId(record.environmentId) }),
    name: requiredText(record.name, "credential"),
    status: record.status,
    scopes: [...record.scopes],
    secret: {
      digest: record.secret.digest,
      ...(reference === undefined ? {} : { reference }),
    },
    fingerprint: requiredText(record.fingerprint, "credential"),
    ...optionalDateField("expiresAt", record.expiresAt),
    ...optionalDateField("rotatedAt", record.rotatedAt),
    ...optionalDateField("revokedAt", record.revokedAt),
    ...optionalTextField("replacedByCredentialId", record.replacedByCredentialId),
    ...optionalTextField("previousCredentialId", record.previousCredentialId),
  };
}

function normalizeUsage(record: UsageRecord, tenantId: string): UsageRecord {
  if (record === null || typeof record !== "object" || record.kind !== "usage") {
    throw validationError("Usage record is invalid");
  }
  if (record.tenantId !== tenantId) throw new TypeError("Open platform tenant scope does not match repository");
  if (record.version !== 1) throw validationError("Usage record version is invalid");
  const quantity = readDecimalQuantity(record.quantity);
  if (quantity === undefined) {
    throw validationError("Usage quantity is invalid");
  }
  return {
    id: normalizeStorageId(record.id),
    tenantId,
    kind: "usage",
    subscriptionId: normalizeStorageId(record.subscriptionId),
    ...optionalTextField("credentialId", record.credentialId),
    productId: normalizeStorageId(record.productId),
    ...optionalTextField("apiVersionId", record.apiVersionId),
    metric: requiredText(record.metric, "usage"),
    quantity,
    occurredAt: requiredDate(record.occurredAt, "usage"),
    idempotencyKey: requiredText(record.idempotencyKey, "usage"),
    version: 1,
    createdAt: requiredDate(record.createdAt, "usage"),
    updatedAt: requiredDate(record.updatedAt, "usage"),
  };
}

function requiredText(value: unknown, kind: string): string {
  const text = readText(value);
  if (text === undefined) throw new Error(`Invalid ${kind} SQL row`);
  return text;
}

function requiredNumber(value: unknown, kind: string): number {
  const number = readNumber(value);
  if (number === undefined) throw new Error(`Invalid ${kind} SQL row`);
  return number;
}

function requiredVersion(value: unknown, kind: string): number {
  const version = requiredNumber(value, kind);
  if (version < 1) throw new Error(`Invalid ${kind} SQL row`);
  return version;
}

function requiredQuantity(value: unknown, kind: string): number {
  const quantity = readDecimalQuantity(value);
  if (quantity === undefined) throw new Error(`Invalid ${kind} SQL row`);
  return quantity;
}

function requiredDate(value: unknown, kind: string): string {
  const date = readDate(value);
  if (date === undefined) throw new Error(`Invalid ${kind} SQL row`);
  return date;
}

function optionalDateField(field: string, value: unknown): Record<string, string> {
  const date = readDate(value);
  return date === undefined ? {} : { [field]: date };
}

function optionalTextField(field: string, value: unknown): Record<string, string> {
  const text = readText(value);
  return text === undefined ? {} : { [field]: text };
}

function sameStringArray(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/u.test(value);
}

export function createSqlTenantRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlTenantRepository {
  return new SqlTenantRepository(input, options);
}

export function createSqlDeveloperOrganizationRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlDeveloperOrganizationRepository {
  return new SqlDeveloperOrganizationRepository(input, options);
}

export function createSqlApplicationRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlApplicationRepository {
  return new SqlApplicationRepository(input, options);
}

export function createSqlApplicationEnvironmentRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlApplicationEnvironmentRepository {
  return new SqlApplicationEnvironmentRepository(input, options);
}

export function createSqlApiProductRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlApiProductRepository {
  return new SqlApiProductRepository(input, options);
}

export function createSqlApiVersionRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlApiVersionRepository {
  return new SqlApiVersionRepository(input, options);
}

export function createSqlCredentialRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlCredentialRepository {
  return new SqlCredentialRepository(input, options);
}

export function createSqlSubscriptionRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlSubscriptionRepository {
  return new SqlSubscriptionRepository(input, options);
}

export function createSqlScopeGrantRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlScopeGrantRepository {
  return new SqlScopeGrantRepository(input, options);
}

export function createSqlUsageRepository(
  input: OpenPlatformSqlRepositoryInput,
  options?: OpenPlatformSqlRepositorySecondOptions,
): SqlUsageRepository {
  return new SqlUsageRepository(input, options);
}

export const PostgresTenantRepository = SqlTenantRepository;
export const PostgresDeveloperOrganizationRepository = SqlDeveloperOrganizationRepository;
export const PostgresApplicationRepository = SqlApplicationRepository;
export const PostgresApplicationEnvironmentRepository = SqlApplicationEnvironmentRepository;
export const PostgresApiProductRepository = SqlApiProductRepository;
export const PostgresApiVersionRepository = SqlApiVersionRepository;
export const PostgresCredentialRepository = SqlCredentialRepository;
export const PostgresSubscriptionRepository = SqlSubscriptionRepository;
export const PostgresScopeGrantRepository = SqlScopeGrantRepository;
export const SqlAppendOnlyUsageRepository = SqlUsageRepository;
export const SqlImmutableUsageRepository = SqlUsageRepository;
export const PostgresUsageRepository = SqlUsageRepository;
export const PostgreSqlTenantRepository = SqlTenantRepository;
export const PostgreSqlDeveloperOrganizationRepository = SqlDeveloperOrganizationRepository;
export const PostgreSqlApplicationRepository = SqlApplicationRepository;
export const PostgreSqlApplicationEnvironmentRepository = SqlApplicationEnvironmentRepository;
export const PostgreSqlApiProductRepository = SqlApiProductRepository;
export const PostgreSqlApiVersionRepository = SqlApiVersionRepository;
export const PostgreSqlCredentialRepository = SqlCredentialRepository;
export const PostgreSqlSubscriptionRepository = SqlSubscriptionRepository;
export const PostgreSqlScopeGrantRepository = SqlScopeGrantRepository;
export const PostgreSqlUsageRepository = SqlUsageRepository;
