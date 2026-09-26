import {
  complianceImmutableRecord,
  complianceResourceConflict,
  complianceResourceNotFound,
  complianceValidationError,
} from "./errors.js";
import { cloneComplianceValue, normalizeComplianceTimestamp } from "./validation.js";
import {
  COMPLIANCE_ENTITY_PREFIXES,
  type ComplianceConsentRecord,
  type ComplianceCrossBorderAssessment,
  type ComplianceDataAsset,
  type ComplianceDependencyReadiness,
  type ComplianceEntityKind,
  type CompliancePrivacyRequest,
  type ComplianceRecord,
  type ComplianceRetentionExecution,
  type ComplianceRetentionPolicy,
  type ComplianceVendor,
} from "./types.js";

export interface ComplianceTenantScopedRepository<T extends ComplianceRecord> {
  create(record: T): Promise<T>;
  get(tenantId: string, id: string): Promise<T | undefined>;
  list(tenantId: string): Promise<T[]>;
  save(record: T): Promise<T>;
  snapshot(tenantId: string): T[];
}

export class InMemoryComplianceRecordStore<T extends ComplianceRecord> {
  private readonly records = new Map<string, T>();
  readonly kind: ComplianceEntityKind;

  constructor(kind: ComplianceEntityKind) {
    this.kind = kind;
  }

  createSynchronously(record: T): T {
    assertRecordIdentity(record, this.kind);
    if (record.version !== 1) {
      throw complianceValidationError(
        "Compliance record version is invalid",
        "version",
      );
    }
    const key = storageKey(record.tenantId, record.id);
    if (this.records.has(key)) throw complianceResourceConflict();
    const stored = cloneComplianceValue(record);
    this.records.set(key, stored);
    return cloneComplianceValue(stored);
  }

  getStored(tenantId: string, id: string): T | undefined {
    const record = this.records.get(storageKey(tenantId, id));
    return record === undefined ? undefined : cloneComplianceValue(record);
  }

  getRaw(tenantId: string, id: string): T | undefined {
    return this.records.get(storageKey(tenantId, id));
  }

  setRaw(record: T): T {
    const stored = cloneComplianceValue(record);
    this.records.set(storageKey(stored.tenantId, stored.id), stored);
    return cloneComplianceValue(stored);
  }

  listStored(tenantId: string): T[] {
    return [...this.records.values()]
      .filter((record) => record.tenantId === tenantId)
      .sort(compareRecords)
      .map((record) => cloneComplianceValue(record));
  }

  replaceSynchronously(record: T): T {
    assertRecordIdentity(record, this.kind);
    const current = this.getRaw(record.tenantId, record.id);
    if (current === undefined) throw complianceResourceNotFound(this.kind);
    if (record.version !== current.version + 1) {
      throw complianceResourceConflict("Compliance record version is stale");
    }
    if (
      record.kind !== current.kind ||
      record.tenantId !== current.tenantId ||
      record.id !== current.id ||
      record.createdAt !== current.createdAt
    ) {
      throw complianceResourceConflict("Compliance record identity is immutable");
    }
    assertImmutableFields(current, record);
    return this.setRaw(record);
  }

  appendOnly(record: T): T {
    assertRecordIdentity(record, this.kind);
    if (record.version !== 1) {
      throw complianceImmutableRecord(this.kind);
    }
    const key = storageKey(record.tenantId, record.id);
    if (this.records.has(key)) throw complianceImmutableRecord(this.kind);
    const stored = cloneComplianceValue(record);
    this.records.set(key, stored);
    return cloneComplianceValue(stored);
  }

  snapshot(tenantId: string): T[] {
    return this.listStored(tenantId);
  }

  count(tenantId: string): number {
    let total = 0;
    for (const record of this.records.values()) {
      if (record.tenantId === tenantId) total += 1;
    }
    return total;
  }
}

export class InMemoryComplianceRepository<T extends ComplianceRecord>
  implements ComplianceTenantScopedRepository<T> {
  protected readonly store: InMemoryComplianceRecordStore<T>;

  constructor(
    kind: ComplianceEntityKind,
    store = new InMemoryComplianceRecordStore<T>(kind),
  ) {
    this.store = store;
  }

  async create(record: T): Promise<T> {
    return this.store.createSynchronously(record);
  }

  async get(tenantId: string, id: string): Promise<T | undefined> {
    return this.store.getStored(tenantId, id);
  }

  async list(tenantId: string): Promise<T[]> {
    return this.store.listStored(tenantId);
  }

  async save(record: T): Promise<T> {
    return this.store.replaceSynchronously(record);
  }

  snapshot(tenantId: string): T[] {
    return this.store.snapshot(tenantId);
  }
}

export class InMemoryDataAssetRepository extends InMemoryComplianceRepository<ComplianceDataAsset> {
  constructor() {
    super("dataAsset");
  }

  async findByCode(
    tenantId: string,
    code: string,
  ): Promise<ComplianceDataAsset | undefined> {
    const normalized = code.trim().toLowerCase();
    return (await this.list(tenantId)).find(
      (record) => record.code.toLowerCase() === normalized,
    );
  }
}

export class InMemoryConsentRepository extends InMemoryComplianceRepository<ComplianceConsentRecord> {
  constructor() {
    super("consentRecord");
  }

  async findActive(
    tenantId: string,
    subjectRef: string,
    purpose: string,
  ): Promise<ComplianceConsentRecord | undefined> {
    const normalizedSubject = subjectRef.trim();
    const normalizedPurpose = purpose.trim();
    return (await this.list(tenantId))
      .filter(
        (record) =>
          record.subjectRef === normalizedSubject &&
          record.purpose === normalizedPurpose &&
          record.status !== "withdrawn" &&
          record.status !== "expired",
      )
      .sort((left, right) =>
        Date.parse(right.createdAt) - Date.parse(left.createdAt),
      )
      .at(0);
  }
}

export class InMemoryPrivacyRequestRepository extends InMemoryComplianceRepository<CompliancePrivacyRequest> {
  constructor() {
    super("privacyRequest");
  }

  async findOpenForSubject(
    tenantId: string,
    subjectRef: string,
    requestType: string,
  ): Promise<CompliancePrivacyRequest | undefined> {
    const normalizedSubject = subjectRef.trim();
    return (await this.list(tenantId))
      .filter(
        (record) =>
          record.subjectRef === normalizedSubject &&
          record.requestType === requestType &&
          !isTerminalPrivacyRequestStatus(record.status),
      )
      .at(0);
  }
}

export class InMemoryRetentionPolicyRepository extends InMemoryComplianceRepository<ComplianceRetentionPolicy> {
  constructor() {
    super("retentionPolicy");
  }

  async findByCode(
    tenantId: string,
    code: string,
  ): Promise<ComplianceRetentionPolicy | undefined> {
    const normalized = code.trim().toLowerCase();
    return (await this.list(tenantId)).find(
      (record) => record.code.toLowerCase() === normalized,
    );
  }
}

export class InMemoryRetentionExecutionRepository extends InMemoryComplianceRepository<ComplianceRetentionExecution> {
  constructor() {
    super("retentionExecution");
  }

  async appendExecution(record: ComplianceRetentionExecution): Promise<ComplianceRetentionExecution> {
    return this.store.appendOnly(record);
  }

  async listByRun(tenantId: string, runId: string): Promise<ComplianceRetentionExecution[]> {
    return (await this.list(tenantId)).filter(
      (record) => record.runId === runId.trim(),
    );
  }
}

export class InMemoryCrossBorderRepository extends InMemoryComplianceRepository<ComplianceCrossBorderAssessment> {
  constructor() {
    super("crossBorderAssessment");
  }

  async findByCode(
    tenantId: string,
    code: string,
  ): Promise<ComplianceCrossBorderAssessment | undefined> {
    const normalized = code.trim().toLowerCase();
    return (await this.list(tenantId)).find(
      (record) => record.code.toLowerCase() === normalized,
    );
  }
}

export class InMemoryVendorRepository extends InMemoryComplianceRepository<ComplianceVendor> {
  constructor() {
    super("vendor");
  }

  async findByCode(tenantId: string, code: string): Promise<ComplianceVendor | undefined> {
    const normalized = code.trim().toLowerCase();
    return (await this.list(tenantId)).find(
      (record) => record.code.toLowerCase() === normalized,
    );
  }
}

export interface InMemoryComplianceRepositoriesOptions {
  readonly production?: boolean;
  readonly ready?: boolean;
}

export class InMemoryComplianceRepositories {
  readonly readiness: ComplianceDependencyReadiness;
  readonly dataAssets = new InMemoryDataAssetRepository();
  readonly consentRecords = new InMemoryConsentRepository();
  readonly privacyRequests = new InMemoryPrivacyRequestRepository();
  readonly retentionPolicies = new InMemoryRetentionPolicyRepository();
  readonly retentionExecutions = new InMemoryRetentionExecutionRepository();
  readonly crossBorderAssessments = new InMemoryCrossBorderRepository();
  readonly vendors = new InMemoryVendorRepository();

  constructor(options: InMemoryComplianceRepositoriesOptions = {}) {
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.ready ?? options.production !== true,
    });
  }

  async isReady(): Promise<boolean> {
    return this.readiness.ready();
  }
}

export function createInMemoryComplianceRepositories(
  options: InMemoryComplianceRepositoriesOptions = {},
): InMemoryComplianceRepositories {
  return new InMemoryComplianceRepositories(options);
}

export function complianceRecordVersion(record: ComplianceRecord): number {
  return record.version;
}

export function isTerminalPrivacyRequestStatus(status: string): boolean {
  return (
    status === "fulfilled" ||
    status === "partiallyFulfilled" ||
    status === "rejected" ||
    status === "cancelled"
  );
}

function assertRecordIdentity(record: ComplianceRecord, kind: ComplianceEntityKind): void {
  if (record === null || typeof record !== "object") {
    throw complianceValidationError("Compliance record is invalid", "record");
  }
  if (record.kind !== kind) {
    throw complianceValidationError("Compliance record kind is invalid", "kind");
  }
  const prefix = COMPLIANCE_ENTITY_PREFIXES[kind];
  if (
    typeof record.id !== "string" ||
    !record.id.startsWith(`${prefix}_`) ||
    typeof record.tenantId !== "string" ||
    record.tenantId.length === 0
  ) {
    throw complianceValidationError("Compliance record identity is invalid", "id");
  }
  if (!Number.isSafeInteger(record.version) || record.version < 1) {
    throw complianceValidationError("Compliance record version is invalid", "version");
  }
  const createdAt = normalizeComplianceTimestamp(record.createdAt, "createdAt");
  const updatedAt = normalizeComplianceTimestamp(record.updatedAt, "updatedAt");
  if (
    createdAt !== record.createdAt ||
    updatedAt !== record.updatedAt ||
    Date.parse(updatedAt) < Date.parse(createdAt)
  ) {
    throw complianceValidationError(
      "Compliance record timestamp is not canonical",
      "createdAt",
    );
  }
}

function assertImmutableFields(
  current: ComplianceRecord,
  next: ComplianceRecord,
): void {
  if (current.kind !== "retentionPolicy" || next.kind !== "retentionPolicy") {
    return;
  }
  const currentPolicy = current as ComplianceRetentionPolicy;
  const nextPolicy = next as ComplianceRetentionPolicy;
  if (
    currentPolicy.code !== nextPolicy.code ||
    currentPolicy.trigger !== nextPolicy.trigger ||
    currentPolicy.action !== nextPolicy.action ||
    currentPolicy.retentionDays !== nextPolicy.retentionDays ||
    currentPolicy.requiresApproval !== nextPolicy.requiresApproval ||
    currentPolicy.legalHold !== nextPolicy.legalHold
  ) {
    throw complianceResourceConflict(
      "Compliance retention policy control fields are immutable",
    );
  }
}

function compareRecords(left: ComplianceRecord, right: ComplianceRecord): number {
  const created = Date.parse(left.createdAt) - Date.parse(right.createdAt);
  if (created !== 0) return created;
  return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}

function storageKey(tenantId: string, id: string): string {
  return `${tenantId} ${id}`;
}
