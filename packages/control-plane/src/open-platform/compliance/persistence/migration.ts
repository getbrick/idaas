import { createHash } from "node:crypto";
import {
  MigrationCoordinator,
  createMigrationDefinition,
  createMigrationMetadataSql,
  migrationChecksum,
  type MigrationDefinition,
  type MigrationDryRunResult,
  type MigrationRunResult,
} from "../../../migration-coordinator.js";
import {
  normalizeTenantConfig,
  qualifyTenantTable,
  type TenantConfig,
  type TenantConfigInput,
} from "../../../tenant.js";
import {
  COMPLIANCE_ASSESSMENT_STATUSES,
  COMPLIANCE_CONSENT_CHANNELS,
  COMPLIANCE_CONSENT_STATUSES,
  COMPLIANCE_CROSS_BORDER_MECHANISMS,
  COMPLIANCE_CROSS_BORDER_STATUSES,
  COMPLIANCE_DATA_ASSET_STATUSES,
  COMPLIANCE_DATA_CATEGORIES,
  COMPLIANCE_DATA_CLASSIFICATIONS,
  COMPLIANCE_DATA_SUBJECT_GROUPS,
  COMPLIANCE_EVIDENCE_KINDS,
  COMPLIANCE_IDENTITY_VERIFICATION_METHODS,
  COMPLIANCE_IDENTITY_VERIFICATION_STATUSES,
  COMPLIANCE_LEGAL_BASES,
  COMPLIANCE_PRIVACY_REQUEST_ACTIONS,
  COMPLIANCE_PRIVACY_REQUEST_DECISIONS,
  COMPLIANCE_PRIVACY_REQUEST_STATUSES,
  COMPLIANCE_PRIVACY_REQUEST_TYPES,
  COMPLIANCE_RETENTION_ACTIONS,
  COMPLIANCE_RETENTION_EXECUTION_STATUSES,
  COMPLIANCE_RETENTION_POLICY_STATUSES,
  COMPLIANCE_RETENTION_TRIGGERS,
  COMPLIANCE_RISK_LEVELS,
  COMPLIANCE_SLA_STATES,
  COMPLIANCE_VENDOR_ROLES,
  COMPLIANCE_VENDOR_STATUSES,
} from "../types.js";

export const OPEN_COMPLIANCE_MIGRATION_VERSION = 1;
export const OPEN_COMPLIANCE_MIGRATION_NAME =
  "open-platform-compliance-persistence-foundation";
export const OPEN_COMPLIANCE_MIGRATION_TABLE =
  "gb_open_compliance_schema_migration";
export const OPEN_COMPLIANCE_MIGRATION_LOCK_TABLE =
  "gb_open_compliance_schema_migration_lock";

export const COMPLIANCE_SQL_TABLES = Object.freeze({
  dataAssets: "gb_open_compliance_data_asset",
  consentRecords: "gb_open_compliance_consent_record",
  privacyRequests: "gb_open_compliance_privacy_request",
  retentionPolicies: "gb_open_compliance_retention_policy",
  retentionExecutions: "gb_open_compliance_retention_execution",
  crossBorderAssessments: "gb_open_compliance_cross_border_assessment",
  vendors: "gb_open_compliance_vendor",
  domainEvents: "gb_open_compliance_event",
} as const satisfies Readonly<Record<string, string>>);

export type ComplianceSqlTableKey = keyof typeof COMPLIANCE_SQL_TABLES;
export const COMPLIANCE_ALL_TABLES = Object.freeze(
  Object.keys(COMPLIANCE_SQL_TABLES) as ComplianceSqlTableKey[],
);

export const COMPLIANCE_APPEND_ONLY_TABLES = Object.freeze([
  "retentionExecutions",
  "domainEvents",
] as const satisfies readonly ComplianceSqlTableKey[]);

export type ComplianceAppendOnlyTableKey =
  (typeof COMPLIANCE_APPEND_ONLY_TABLES)[number];

export const COMPLIANCE_SQL_COLUMNS = Object.freeze({
  id: "id",
  tenantId: "tenant_id",
  kind: "kind",
  version: "version",
  status: "status",
  createdAt: "created_at",
  updatedAt: "updated_at",
  code: "code",
  name: "name",
  classification: "classification",
  categories: "categories",
  personalData: "personal_data",
  sensitivePersonalData: "sensitive_personal_data",
  legalBasis: "legal_basis",
  purposes: "purposes",
  dataSubjects: "data_subjects",
  residencyRegions: "residency_regions",
  processorVendorId: "processor_vendor_id",
  retentionPolicyId: "retention_policy_id",
  retentionDays: "retention_days",
  crossBorder: "cross_border",
  evidence: "evidence",
  subjectRef: "subject_ref",
  subjectCount: "subject_count",
  purpose: "purpose",
  policyVersion: "policy_version",
  channel: "channel",
  language: "language",
  scopes: "scopes",
  dataAssetIds: "data_asset_ids",
  grantedAt: "granted_at",
  withdrawnAt: "withdrawn_at",
  expiresAt: "expires_at",
  withdrawalReason: "withdrawal_reason",
  proof: "proof",
  requestType: "request_type",
  statusReason: "status_reason",
  identityStatus: "identity_verification_status",
  identityMethod: "identity_verification_method",
  identityAttempts: "identity_verification_attempts",
  identityVerifiedAt: "identity_verified_at",
  identityVerifiedBy: "identity_verified_by",
  identityEvidence: "identity_evidence",
  slaPolicyCode: "sla_policy_code",
  slaResponseDays: "sla_response_days",
  slaDueAt: "sla_due_at",
  slaRespondedAt: "sla_responded_at",
  slaClosedAt: "sla_closed_at",
  slaState: "sla_state",
  decision: "decision",
  decidedAt: "decided_at",
  decidedBy: "decided_by",
  rationale: "rationale",
  decisionEvidence: "decision_evidence",
  actions: "actions",
  duplicateOfId: "duplicate_of_id",
  trigger: "trigger",
  action: "action",
  requiresApproval: "requires_approval",
  legalHold: "legal_hold",
  lastExecutionId: "last_execution_id",
  policyId: "policy_id",
  runId: "run_id",
  blockedReason: "blocked_reason",
  result: "result",
  recordedBy: "recorded_by",
  occurredAt: "occurred_at",
  title: "title",
  sourceRegion: "source_region",
  destinationRegions: "destination_regions",
  transferPurpose: "transfer_purpose",
  riskLevel: "risk_level",
  riskFactors: "risk_factors",
  mechanisms: "mechanisms",
  recipientVendorId: "recipient_vendor_id",
  validUntil: "valid_until",
  role: "role",
  legalName: "legal_name",
  displayName: "display_name",
  regions: "regions",
  parentVendorId: "parent_vendor_id",
  contractEffectiveAt: "contract_effective_at",
  contractTerminatedAt: "contract_terminated_at",
  assessment: "assessment",
  eventType: "event_type",
  fromStatus: "from_status",
  toStatus: "to_status",
  actorRef: "actor_ref",
  sequence: "sequence",
  recordId: "record_id",
  metadata: "metadata",
  previousHash: "previous_hash",
  eventHash: "event_hash",
} as const);

export type ComplianceSqlColumnKey = keyof typeof COMPLIANCE_SQL_COLUMNS;
export type ComplianceSqlColumns = Readonly<Record<ComplianceSqlColumnKey, string>>;

export interface ComplianceDatabaseAdapter {
  query(sql: string, values?: readonly unknown[]): Promise<unknown>;
}

export interface OpenComplianceMigrationOptions {
  readonly schema?: string;
  readonly mode?: string;
  readonly tenantId?: string;
  readonly tenantColumn?: string | null;
  readonly tenant?: TenantConfigInput;
  readonly tenantConfig?: TenantConfigInput;
  readonly tenantMode?: string;
  readonly includeRls?: boolean;
  readonly requireRls?: boolean;
  readonly requireTransaction?: boolean;
  readonly requireTransactions?: boolean;
  readonly allowNonTransactional?: boolean;
  readonly tables?: Partial<Record<ComplianceSqlTableKey, string>>;
  readonly columns?: Partial<Record<ComplianceSqlColumnKey, string>>;
  readonly migrationTable?: string;
  readonly migrationLockTable?: string;
  readonly migrationVersion?: number;
  readonly migrationName?: string;
  readonly includeMigrationMetadata?: boolean;
  readonly lockKey?: string | number;
  readonly lockNamespace?: string;
  readonly ownerId?: string;
  readonly clock?: () => Date;
}

export type ComplianceMigrationOptions = OpenComplianceMigrationOptions;

export function createOpenComplianceMigrationSql(
  options: OpenComplianceMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = migrationTables(options, tenant.schema);
  const columns = migrationColumns(options, tenant.tenantColumn);
  const statements: string[] = [
    createDataAssetTable(tables, columns),
    createConsentRecordTable(tables, columns),
    createPrivacyRequestTable(tables, columns),
    createRetentionPolicyTable(tables, columns),
    createRetentionExecutionTable(tables, columns),
    createCrossBorderAssessmentTable(tables, columns),
    createVendorTable(tables, columns),
    createDomainEventTable(tables, columns),
    ...indexes(tables, columns),
    ...uniqueConstraints(tables, columns),
    ...immutabilityStatements(tables, columns),
    ...retentionPolicyImmutability(tables, columns),
  ];
  if (options.includeRls !== false) {
    statements.push(...rlsStatements(tables, columns, tenant.tenantColumn));
  }
  if (options.includeMigrationMetadata !== false) {
    statements.push(
      createMigrationMetadataSql({
        tableName: qualifyMigrationTable(
          options.migrationTable ?? OPEN_COMPLIANCE_MIGRATION_TABLE,
          tenant.schema,
          "compliance migration table",
        ),
        lockTableName: qualifyMigrationTable(
          options.migrationLockTable ?? OPEN_COMPLIANCE_MIGRATION_LOCK_TABLE,
          tenant.schema,
          "compliance migration lock table",
        ),
      }),
    );
  }
  return `${statements.join(";\n")};\n`;
}

export const createComplianceMigrationSql = createOpenComplianceMigrationSql;
export const getOpenComplianceMigrationSql = createOpenComplianceMigrationSql;
export const getComplianceMigrationSql = createOpenComplianceMigrationSql;
export const createOpenPlatformComplianceMigrationSql =
  createOpenComplianceMigrationSql;
export const OPEN_COMPLIANCE_MIGRATION_SQL = createOpenComplianceMigrationSql();

export function getOpenComplianceMigrationDefinition(
  options: OpenComplianceMigrationOptions = {},
): MigrationDefinition {
  const tenant = migrationTenant(options);
  return createMigrationDefinition(
    options.migrationVersion ?? OPEN_COMPLIANCE_MIGRATION_VERSION,
    options.migrationName ?? OPEN_COMPLIANCE_MIGRATION_NAME,
    createOpenComplianceMigrationSql(options),
    {
      component: "open-platform-compliance-persistence",
      tenantMode: tenant.mode,
      tenantId: tenant.tenantId,
      schema: tenant.schema,
      tables: COMPLIANCE_SQL_TABLES,
      appendOnlyTables: COMPLIANCE_APPEND_ONLY_TABLES,
      redaction: "raw personal information must never be stored in these tables",
      checksumAlgorithm: "sha256",
    },
    `open-platform-compliance:${tenant.mode}:${tenant.schema}:${tenant.tenantId}`,
  );
}

export const getComplianceMigrationDefinition =
  getOpenComplianceMigrationDefinition;
export const createComplianceMigrationDefinition =
  getOpenComplianceMigrationDefinition;

export function getOpenComplianceMigrationChecksum(
  options: OpenComplianceMigrationOptions = {},
): string {
  return migrationChecksum(createOpenComplianceMigrationSql(options));
}

export const getComplianceMigrationChecksum = getOpenComplianceMigrationChecksum;

export function createOpenComplianceMigrationPlan(
  options: OpenComplianceMigrationOptions = {},
): { version: number; name: string; checksum: string; sql: string } {
  const definition = getOpenComplianceMigrationDefinition(options);
  return {
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
    sql: definition.sql,
  };
}

export const getOpenComplianceMigrationPlan = createOpenComplianceMigrationPlan;
export const getComplianceMigrationPlan = createOpenComplianceMigrationPlan;

export function dryRunOpenComplianceMigration(
  options?: OpenComplianceMigrationOptions,
): MigrationDryRunResult;
export function dryRunOpenComplianceMigration(
  adapter: ComplianceDatabaseAdapter,
  options?: OpenComplianceMigrationOptions,
): MigrationDryRunResult;
export function dryRunOpenComplianceMigration(
  input: ComplianceDatabaseAdapter | OpenComplianceMigrationOptions = {},
  second: OpenComplianceMigrationOptions = {},
): MigrationDryRunResult {
  const hasAdapter = isAdapter(input);
  const options = hasAdapter ? second : input;
  const definition = getOpenComplianceMigrationDefinition(options);
  const coordinator = new MigrationCoordinator(
    hasAdapter ? input : { query: async () => ({ rows: [] }) },
    [definition],
    coordinatorOptions(options, false),
  );
  return coordinator.dryRun([definition]);
}

export async function applyVersionedOpenComplianceMigration(
  adapter: ComplianceDatabaseAdapter,
  options: OpenComplianceMigrationOptions = {},
): Promise<MigrationRunResult> {
  const definition = getOpenComplianceMigrationDefinition(options);
  const coordinator = new MigrationCoordinator(
    adapter,
    [definition],
    coordinatorOptions(
      options,
      options.requireTransaction ?? options.allowNonTransactional !== true,
    ),
  );
  return coordinator.run([definition]);
}

export async function applyOpenComplianceMigration(
  adapter: ComplianceDatabaseAdapter,
  options: OpenComplianceMigrationOptions = {},
): Promise<void> {
  await applyVersionedOpenComplianceMigration(adapter, options);
}

export const runOpenComplianceMigration = applyVersionedOpenComplianceMigration;
export const applyComplianceMigration = applyVersionedOpenComplianceMigration;
export const runComplianceMigration = applyVersionedOpenComplianceMigration;
export const applyOpenPlatformComplianceMigration =
  applyVersionedOpenComplianceMigration;

export function validateComplianceSqlIdentifier(
  value: string,
  field = "SQL identifier",
): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${field} is invalid`);
  }
  const segments = value.split(".");
  for (const segment of segments) {
    if (!/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/u.test(segment)) {
      throw new TypeError(`${field} is invalid`);
    }
  }
  return segments.map((segment) => segment.trim()).join(".");
}

function createDataAssetTable(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string {
  return createTable(tables.dataAssets, [
    ...commonColumns(c, "dataAsset", COMPLIANCE_DATA_ASSET_STATUSES),
    textColumn(c.name, false),
    textColumn(c.code, false),
    enumColumn(c.classification, COMPLIANCE_DATA_CLASSIFICATIONS, false),
    jsonArray(c.categories),
    booleanColumn(c.personalData, false, false),
    booleanColumn(c.sensitivePersonalData, false, false),
    enumColumn(c.legalBasis, COMPLIANCE_LEGAL_BASES, true),
    jsonArray(c.purposes),
    jsonArray(c.dataSubjects),
    jsonArray(c.residencyRegions),
    textColumn(c.processorVendorId, true),
    textColumn(c.retentionPolicyId, true),
    integerColumn(c.retentionDays, true, 1, 36500),
    booleanColumn(c.crossBorder, false, false),
    jsonArray(c.evidence),
  ]);
}

function createConsentRecordTable(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string {
  return createTable(tables.consentRecords, [
    ...commonColumns(c, "consentRecord", COMPLIANCE_CONSENT_STATUSES),
    textColumn(c.subjectRef, false),
    integerColumn(c.subjectCount, false, 1, 1000000),
    textColumn(c.purpose, false),
    literalColumn(c.legalBasis, "consent"),
    textColumn(c.policyVersion, false),
    enumColumn(c.channel, COMPLIANCE_CONSENT_CHANNELS, false),
    textColumn(c.language, true),
    jsonArray(c.scopes),
    jsonArray(c.dataAssetIds),
    timestampColumn(c.grantedAt, true),
    timestampColumn(c.withdrawnAt, true),
    timestampColumn(c.expiresAt, true),
    textColumn(c.withdrawalReason, true),
    jsonArray(c.proof),
    check(
      `(${q(c.status)} = 'withdrawn' AND ${q(c.withdrawnAt)} IS NOT NULL) OR ${q(c.status)} <> 'withdrawn'`,
    ),
  ]);
}

function createPrivacyRequestTable(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string {
  return createTable(tables.privacyRequests, [
    ...commonColumns(c, "privacyRequest", COMPLIANCE_PRIVACY_REQUEST_STATUSES),
    enumColumn(c.requestType, COMPLIANCE_PRIVACY_REQUEST_TYPES, false),
    textColumn(c.statusReason, true),
    textColumn(c.subjectRef, false),
    integerColumn(c.subjectCount, false, 1, 1000000),
    jsonArray(c.dataAssetIds),
    enumColumn(
      c.identityStatus,
      COMPLIANCE_IDENTITY_VERIFICATION_STATUSES,
      false,
    ),
    enumColumn(
      c.identityMethod,
      COMPLIANCE_IDENTITY_VERIFICATION_METHODS,
      true,
    ),
    integerColumn(c.identityAttempts, false, 0, 1000),
    timestampColumn(c.identityVerifiedAt, true),
    textColumn(c.identityVerifiedBy, true),
    jsonArray(c.identityEvidence),
    textColumn(c.slaPolicyCode, false),
    integerColumn(c.slaResponseDays, false, 1, 365),
    timestampColumn(c.slaDueAt, false),
    timestampColumn(c.slaRespondedAt, true),
    timestampColumn(c.slaClosedAt, true),
    enumColumn(c.slaState, COMPLIANCE_SLA_STATES, false),
    enumColumn(c.decision, COMPLIANCE_PRIVACY_REQUEST_DECISIONS, true),
    timestampColumn(c.decidedAt, true),
    textColumn(c.decidedBy, true),
    textColumn(c.rationale, true),
    jsonArray(c.decisionEvidence),
    jsonArray(c.actions),
    textColumn(c.duplicateOfId, true),
    check(
      `${q(c.status)} NOT IN ('fulfilled', 'partiallyFulfilled') OR ${q(c.identityStatus)} = 'verified'`,
    ),
  ]);
}

function createRetentionPolicyTable(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string {
  return createTable(tables.retentionPolicies, [
    ...commonColumns(c, "retentionPolicy", COMPLIANCE_RETENTION_POLICY_STATUSES),
    textColumn(c.name, false),
    textColumn(c.code, false),
    enumColumn(c.trigger, COMPLIANCE_RETENTION_TRIGGERS, false),
    enumColumn(c.action, COMPLIANCE_RETENTION_ACTIONS, false),
    integerColumn(c.retentionDays, false, 1, 36500),
    booleanColumn(c.requiresApproval, false, false),
    booleanColumn(c.legalHold, false, false),
    jsonArray(c.dataAssetIds),
    jsonArray(c.residencyRegions),
    textColumn(c.lastExecutionId, true),
    jsonArray(c.evidence),
  ]);
}

function createRetentionExecutionTable(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string {
  return createTable(tables.retentionExecutions, [
    ...commonColumns(c, "retentionExecution", COMPLIANCE_RETENTION_EXECUTION_STATUSES),
    textColumn(c.policyId, false),
    jsonArray(c.dataAssetIds),
    enumColumn(c.action, COMPLIANCE_RETENTION_ACTIONS, false),
    textColumn(c.runId, false),
    textColumn(c.blockedReason, true),
    jsonObject(c.result),
    textColumn(c.recordedBy, false),
    timestampColumn(c.occurredAt, false),
    check(`${q(c.version)} = 1`),
  ]);
}

function createCrossBorderAssessmentTable(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string {
  return createTable(tables.crossBorderAssessments, [
    ...commonColumns(c, "crossBorderAssessment", COMPLIANCE_CROSS_BORDER_STATUSES),
    textColumn(c.title, false),
    textColumn(c.code, false),
    textColumn(c.sourceRegion, false),
    jsonArray(c.destinationRegions),
    textColumn(c.transferPurpose, false),
    jsonArray(c.dataAssetIds),
    booleanColumn(c.personalData, false, false),
    booleanColumn(c.sensitivePersonalData, false, false),
    enumColumn(c.riskLevel, COMPLIANCE_RISK_LEVELS, false),
    jsonArray(c.riskFactors),
    jsonArray(c.mechanisms),
    textColumn(c.recipientVendorId, true),
    timestampColumn(c.decidedAt, true),
    textColumn(c.decidedBy, true),
    timestampColumn(c.validUntil, true),
    jsonArray(c.evidence),
    check(
      `${q(c.status)} <> 'approved' OR jsonb_array_length(${q(c.mechanisms)}) > 0 OR ${q(c.personalData)} = false`,
    ),
  ]);
}

function createVendorTable(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string {
  return createTable(tables.vendors, [
    ...commonColumns(c, "vendor", COMPLIANCE_VENDOR_STATUSES),
    enumColumn(c.role, COMPLIANCE_VENDOR_ROLES, false),
    textColumn(c.code, false),
    textColumn(c.legalName, false),
    textColumn(c.displayName, true),
    jsonArray(c.regions),
    jsonArray(c.dataAssetIds),
    jsonArray(c.categories),
    textColumn(c.parentVendorId, true),
    booleanColumn(c.crossBorder, false, false),
    timestampColumn(c.contractEffectiveAt, true),
    timestampColumn(c.contractTerminatedAt, true),
    jsonObject(c.assessment),
    jsonArray(c.evidence),
    check(
      `${q(c.role)} <> 'subProcessor' OR ${q(c.parentVendorId)} IS NOT NULL`,
    ),
    check(
      `${q(c.status)} <> 'active' OR (${q(c.assessment)} ->> 'status') = 'passed'`,
    ),
  ]);
}

function createDomainEventTable(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string {
  return createTable(tables.domainEvents, [
    `${q(c.id)} TEXT NOT NULL`,
    `${q(c.tenantId)} TEXT NOT NULL`,
    `${q(c.kind)} TEXT NOT NULL`,
    `${q(c.eventType)} TEXT NOT NULL`,
    textColumn(c.recordId, false),
    textColumn(c.fromStatus, true),
    textColumn(c.toStatus, true),
    textColumn(c.actorRef, false),
    timestampColumn(c.occurredAt, false),
    jsonArray(c.dataAssetIds),
    jsonObject(c.metadata),
    integerColumn(c.sequence, false, 1, 1000000000),
    textColumn(c.previousHash, true),
    `${q(c.eventHash)} TEXT NOT NULL CHECK (${q(c.eventHash)} ~ '^[a-f0-9]{64}$')`,
    `PRIMARY KEY (${q(c.tenantId)}, ${q(c.sequence)})`,
  ]);
}

function indexes(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string[] {
  return [
    index(tables.dataAssets, "status_idx", [c.tenantId, c.status, c.createdAt]),
    index(tables.dataAssets, "classification_idx", [
      c.tenantId,
      c.classification,
      c.sensitivePersonalData,
    ]),
    index(tables.consentRecords, "subject_idx", [c.tenantId, c.subjectRef, c.status]),
    index(tables.consentRecords, "status_idx", [c.tenantId, c.status, c.createdAt]),
    index(tables.privacyRequests, "status_idx", [
      c.tenantId,
      c.status,
      c.slaDueAt,
    ]),
    index(tables.privacyRequests, "sla_idx", [c.tenantId, c.slaState, c.slaDueAt]),
    index(tables.privacyRequests, "subject_idx", [c.tenantId, c.subjectRef]),
    index(tables.retentionPolicies, "status_idx", [c.tenantId, c.status]),
    index(tables.retentionExecutions, "policy_idx", [
      c.tenantId,
      c.policyId,
      c.occurredAt,
    ]),
    index(tables.retentionExecutions, "run_idx", [c.tenantId, c.runId, c.occurredAt]),
    index(tables.crossBorderAssessments, "status_idx", [c.tenantId, c.status]),
    index(tables.crossBorderAssessments, "risk_idx", [c.tenantId, c.riskLevel, c.status]),
    index(tables.vendors, "status_idx", [c.tenantId, c.status, c.role]),
    index(tables.vendors, "parent_idx", [c.tenantId, c.parentVendorId]),
    index(tables.domainEvents, "record_idx", [c.tenantId, c.recordId, c.sequence]),
  ];
}

function uniqueConstraints(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string[] {
  return [
    uniqueIndex(tables.dataAssets, "code_uq", [c.tenantId, `LOWER(${q(c.code)})`]),
    uniqueIndex(tables.retentionPolicies, "code_uq", [
      c.tenantId,
      `LOWER(${q(c.code)})`,
    ]),
    uniqueIndex(tables.crossBorderAssessments, "code_uq", [
      c.tenantId,
      `LOWER(${q(c.code)})`,
    ]),
    uniqueIndex(tables.vendors, "code_uq", [c.tenantId, `LOWER(${q(c.code)})`]),
    uniqueIndex(tables.domainEvents, "record_uq", [c.tenantId, c.recordId, c.sequence]),
  ];
}

function immutabilityStatements(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string[] {
  const statements: string[] = [];
  for (const key of COMPLIANCE_APPEND_ONLY_TABLES) {
    const table = tables[key];
    const functionName = qualifyFunctionName(
      table,
      `gb_open_compliance_reject_${snake(key)}_mutation`,
    );
    statements.push(
      `CREATE OR REPLACE FUNCTION ${q(functionName)}() RETURNS trigger LANGUAGE plpgsql AS $gb_open$ BEGIN RAISE EXCEPTION 'gb_open_compliance ${key} is append-only' USING ERRCODE = '55000'; END; $gb_open$`,
      `DROP TRIGGER IF EXISTS ${q(objectName(table, "append_only"))} ON ${q(table)}`,
      `CREATE TRIGGER ${q(objectName(table, "append_only"))} BEFORE UPDATE OR DELETE ON ${q(table)} FOR EACH ROW EXECUTE FUNCTION ${q(functionName)}()`,
    );
  }
  void c;
  return statements;
}

function retentionPolicyImmutability(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
): string[] {
  const table = tables.retentionPolicies;
  const functionName = qualifyFunctionName(
    table,
    "gb_open_compliance_reject_retention_policy_mutation",
  );
  const immutable = [
    c.tenantId,
    c.id,
    c.kind,
    c.code,
    c.trigger,
    c.action,
    c.retentionDays,
    c.requiresApproval,
    c.legalHold,
    c.createdAt,
  ];
  return [
    `CREATE OR REPLACE FUNCTION ${q(functionName)}() RETURNS trigger LANGUAGE plpgsql AS $gb_open$ BEGIN IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'gb_open_compliance_retention_policy is immutable' USING ERRCODE = '55000'; END IF; ${immutable
      .map(
        (column) =>
          `IF NEW.${q(column)} IS DISTINCT FROM OLD.${q(column)} THEN RAISE EXCEPTION 'gb_open_compliance_retention_policy control fields are immutable' USING ERRCODE = '55000'; END IF;`,
      )
      .join(" ")} RETURN NEW; END; $gb_open$`,
    `DROP TRIGGER IF EXISTS ${q(objectName(table, "immutable"))} ON ${q(table)}`,
    `CREATE TRIGGER ${q(objectName(table, "immutable"))} BEFORE UPDATE OR DELETE ON ${q(table)} FOR EACH ROW EXECUTE FUNCTION ${q(functionName)}()`,
  ];
}

function rlsStatements(
  tables: Record<ComplianceSqlTableKey, string>,
  c: ComplianceSqlColumns,
  tenantColumn: string,
): string[] {
  const statements: string[] = [];
  for (const key of COMPLIANCE_ALL_TABLES) {
    const table = tables[key];
    const column = key === "domainEvents" ? tenantColumn : c.tenantId;
    const policy = objectName(table, "tenant_policy");
    statements.push(
      `ALTER TABLE ${q(table)} ENABLE ROW LEVEL SECURITY`,
      `ALTER TABLE ${q(table)} FORCE ROW LEVEL SECURITY`,
      `DROP POLICY IF EXISTS ${q(policy)} ON ${q(table)}`,
      `CREATE POLICY ${q(policy)} ON ${q(table)} USING (${q(column)} = current_setting('app.tenant_id', true)) WITH CHECK (${q(column)} = current_setting('app.tenant_id', true))`,
    );
  }
  return statements;
}

function commonColumns(
  c: ComplianceSqlColumns,
  kind: string,
  statuses: readonly string[],
): string[] {
  return [
    `${q(c.id)} TEXT NOT NULL`,
    `${q(c.tenantId)} TEXT NOT NULL`,
    `${q(c.kind)} TEXT NOT NULL DEFAULT '${kind}' CHECK (${q(c.kind)} = '${kind}')`,
    `${q(c.status)} TEXT NOT NULL CHECK (${q(c.status)} IN (${statuses
      .map((status) => `'${status}'`)
      .join(", ")}))`,
    `${q(c.version)} INTEGER NOT NULL DEFAULT 1 CHECK (${q(c.version)} > 0)`,
    timestampColumn(c.createdAt, false),
    timestampColumn(c.updatedAt, false),
    check(`${q(c.updatedAt)} >= ${q(c.createdAt)}`),
    `PRIMARY KEY (${q(c.tenantId)}, ${q(c.id)})`,
  ];
}

function createTable(table: string, definitions: string[]): string {
  return `CREATE TABLE IF NOT EXISTS ${q(table)} (${definitions.join(", ")})`;
}

function check(expression: string): string {
  return `CHECK (${expression})`;
}

function textColumn(column: string, optional: boolean): string {
  return `${q(column)} TEXT${optional ? "" : " NOT NULL"}`;
}

function literalColumn(column: string, value: string): string {
  return `${q(column)} TEXT NOT NULL DEFAULT '${value}' CHECK (${q(column)} = '${value}')`;
}

function enumColumn(
  column: string,
  values: readonly string[],
  optional: boolean,
): string {
  const allowed = values.map((value) => `'${value}'`).join(", ");
  return optional
    ? `${q(column)} TEXT CHECK (${q(column)} IS NULL OR ${q(column)} IN (${allowed}))`
    : `${q(column)} TEXT NOT NULL CHECK (${q(column)} IN (${allowed}))`;
}

function booleanColumn(column: string, optional: boolean, defaultValue: boolean): string {
  return `${q(column)} BOOLEAN${optional ? "" : ` NOT NULL DEFAULT ${defaultValue}`}`;
}

function integerColumn(
  column: string,
  optional: boolean,
  min: number,
  max: number,
): string {
  return `${q(column)} INTEGER${optional ? "" : " NOT NULL"} CHECK (${q(column)} BETWEEN ${min} AND ${max})`;
}

function timestampColumn(column: string, optional: boolean): string {
  return `${q(column)} TIMESTAMPTZ${optional ? "" : " NOT NULL"}`;
}

function jsonArray(column: string): string {
  return `${q(column)} JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(${q(column)}) = 'array')`;
}

function jsonObject(column: string): string {
  return `${q(column)} JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(${q(column)}) = 'object')`;
}

function index(table: string, suffix: string, columns: readonly string[]): string {
  return `CREATE INDEX IF NOT EXISTS ${q(objectName(table, suffix))} ON ${q(table)} (${columns
    .map((column) => (column.includes("(") ? column : q(column)))
    .join(", ")})`;
}

function uniqueIndex(
  table: string,
  suffix: string,
  columns: readonly string[],
): string {
  return `CREATE UNIQUE INDEX IF NOT EXISTS ${q(objectName(table, suffix))} ON ${q(table)} (${columns
    .map((column) => (column.includes("(") ? column : q(column)))
    .join(", ")})`;
}

function migrationTenant(options: OpenComplianceMigrationOptions): TenantConfig {
  return normalizeTenantConfig({
    ...(options.tenant ?? {}),
    ...(options.tenantConfig ?? {}),
    ...(options.schema === undefined ? {} : { schema: options.schema }),
    ...(options.mode === undefined ? {} : { mode: options.mode }),
    ...(options.tenantMode === undefined ? {} : { mode: options.tenantMode }),
    ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
    ...(options.tenantColumn === undefined
      ? {}
      : { tenantColumn: options.tenantColumn }),
    requireRls: options.requireRls ?? options.includeRls !== false,
    requireTransactions: options.requireTransactions ?? true,
  });
}

function migrationTables(
  options: OpenComplianceMigrationOptions,
  schema: string,
): Record<ComplianceSqlTableKey, string> {
  const tables = {} as Record<ComplianceSqlTableKey, string>;
  for (const key of COMPLIANCE_ALL_TABLES) {
    const value = options.tables?.[key] ?? COMPLIANCE_SQL_TABLES[key];
    tables[key] = qualifyTenantTable(
      validateComplianceSqlIdentifier(value, "compliance table"),
      schema,
    );
  }
  return tables;
}

function migrationColumns(
  options: OpenComplianceMigrationOptions,
  tenantColumn: string,
): ComplianceSqlColumns {
  const columns = {} as Record<ComplianceSqlColumnKey, string>;
  for (const key of Object.keys(COMPLIANCE_SQL_COLUMNS) as ComplianceSqlColumnKey[]) {
    columns[key] = validateComplianceSqlIdentifier(
      options.columns?.[key] ?? COMPLIANCE_SQL_COLUMNS[key],
      "compliance column",
    );
  }
  columns.tenantId = validateComplianceSqlIdentifier(
    options.columns?.tenantId ?? tenantColumn,
    "compliance tenant column",
  );
  return columns;
}

function coordinatorOptions(
  options: OpenComplianceMigrationOptions,
  requireTransaction: boolean,
): {
  tableName: string;
  lockTableName: string;
  lockKey: string;
  lockNamespace: string;
  scope: string;
  ownerId?: string;
  requireTransaction: boolean;
  clock?: () => Date;
} {
  const tenant = migrationTenant(options);
  return {
    tableName: qualifyMigrationTable(
      options.migrationTable ?? OPEN_COMPLIANCE_MIGRATION_TABLE,
      tenant.schema,
      "compliance migration table",
    ),
    lockTableName: qualifyMigrationTable(
      options.migrationLockTable ?? OPEN_COMPLIANCE_MIGRATION_LOCK_TABLE,
      tenant.schema,
      "compliance migration lock table",
    ),
    lockKey: String(options.lockKey ?? "getbrick-open-compliance-schema"),
    lockNamespace:
      options.lockNamespace ?? `open-platform-compliance:${tenant.schema}`,
    scope: `open-platform-compliance:${tenant.mode}:${tenant.schema}:${tenant.tenantId}`,
    ...(options.ownerId === undefined ? {} : { ownerId: options.ownerId }),
    requireTransaction,
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  };
}

function qualifyMigrationTable(value: string, schema: string, field: string): string {
  return qualifyTenantTable(
    validateComplianceSqlIdentifier(value, field),
    schema,
  );
}

function qualifyFunctionName(table: string, functionName: string): string {
  const segments = table.split(".");
  return segments.length === 2 ? `${segments[0]}.${functionName}` : functionName;
}

function objectName(table: string, suffix: string): string {
  const base = table.split(".").at(-1) ?? table;
  const digest = createHash("sha256")
    .update(`${base}.${suffix}`, "utf8")
    .digest("hex")
    .slice(0, 8);
  const available = Math.max(1, 63 - suffix.length - digest.length - 2);
  return `${base.slice(0, available)}_${suffix}_${digest}`;
}

function snake(value: string): string {
  return value.replace(/[A-Z]/gu, (character) => `_${character.toLowerCase()}`);
}

function q(value: string): string {
  return validateComplianceSqlIdentifier(value, "SQL identifier")
    .split(".")
    .map((segment) => `"${segment}"`)
    .join(".");
}

function isAdapter(value: unknown): value is ComplianceDatabaseAdapter {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { query?: unknown }).query === "function"
  );
}

export const COMPLIANCE_EVIDENCE_KINDS_SQL = COMPLIANCE_EVIDENCE_KINDS;
export const COMPLIANCE_PRIVACY_REQUEST_ACTIONS_SQL = COMPLIANCE_PRIVACY_REQUEST_ACTIONS;
export const COMPLIANCE_ASSESSMENT_STATUSES_SQL = COMPLIANCE_ASSESSMENT_STATUSES;
