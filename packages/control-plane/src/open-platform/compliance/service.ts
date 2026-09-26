import type { OpenPlatformComplianceReport } from "@getbrick/idaas-contracts";
import { randomUUID } from "node:crypto";
import {
  COMPLIANCE_ERROR_CODES,
  complianceCrossBorderMechanismRequired,
  complianceIdentityVerificationRequired,
  complianceLegalBasisRequired,
  complianceResourceConflict,
  complianceResourceNotFound,
  complianceStorageUnavailable,
  complianceValidationError,
  isOpenPlatformComplianceError,
} from "./errors.js";
import {
  COMPLIANCE_AUDIT_SOURCE,
  InMemoryComplianceAuditStore,
  InMemoryComplianceEventStore,
  complianceStatusTransitionEventType,
  type ComplianceAuditActor,
  type ComplianceAuditEventInput,
  type ComplianceAuditPort,
  type ComplianceAuditRecord,
  type ComplianceEventInput,
  type ComplianceEventPort,
  type ComplianceEventRecord,
} from "./events.js";
import {
  complianceDomainEventAuditTargetType,
  complianceDomainEventDescriptor,
  complianceDomainEventId,
  complianceDomainEventIdempotencyKey,
  complianceDomainEventPublisherReadiness,
  complianceDomainEventPublisherReady,
  complianceDomainEventTarget,
  isComplianceEventPublisher,
  type ComplianceDomainEventReadiness,
  type ComplianceDomainEventScope,
  type ComplianceDomainEventTarget,
  type ComplianceDomainEventTransition,
} from "./outbox.js";
import { InMemoryComplianceRepositories } from "./repositories.js";
import { buildComplianceReport } from "./report.js";
import {
  COMPLIANCE_STATEFUL_ENTITY_KINDS,
  assertConsentTransition,
  assertCrossBorderTransition,
  assertDataAssetTransition,
  assertPrivacyRequestTransition,
  assertRetentionPolicyTransition,
  assertVendorTransition,
  isPrivacyRequestTerminalStatus,
  privacyRequestRequiresDecision,
  privacyRequestRequiresIdentityVerification,
  type ComplianceStatefulEntityKind,
} from "./state-machine.js";
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
  COMPLIANCE_DEFAULT_SLA_POLICY_CODE,
  COMPLIANCE_ENTITY_PREFIXES,
  COMPLIANCE_EVIDENCE_KINDS,
  COMPLIANCE_IDENTITY_VERIFICATION_METHODS,
  COMPLIANCE_IDENTITY_VERIFICATION_STATUSES,
  COMPLIANCE_LEGAL_BASES,
  COMPLIANCE_MAX_RESPONSE_DAYS,
  COMPLIANCE_PRIVACY_REQUEST_ACTIONS,
  COMPLIANCE_PRIVACY_REQUEST_DECISIONS,
  COMPLIANCE_PRIVACY_REQUEST_STATUSES,
  COMPLIANCE_PRIVACY_REQUEST_TYPES,
  COMPLIANCE_RETENTION_ACTIONS,
  COMPLIANCE_RETENTION_EXECUTION_STATUSES,
  COMPLIANCE_RETENTION_POLICY_STATUSES,
  COMPLIANCE_RETENTION_TRIGGERS,
  COMPLIANCE_RISK_LEVELS,
  COMPLIANCE_SLA_DUE_SOON_DAYS,
  COMPLIANCE_VENDOR_ROLES,
  COMPLIANCE_VENDOR_STATUSES,
  type ComplianceConsentChannel,
  type ComplianceConsentRecord,
  type ComplianceCrossBorderAssessment,
  type ComplianceCrossBorderMechanism,
  type ComplianceDataAsset,
  type ComplianceDataAssetStatus,
  type ComplianceDataCategory,
  type ComplianceEntityKind,
  type ComplianceEvidence,
  type ComplianceIdentityVerificationMethod,
  type ComplianceIdentityVerificationStatus,
  type ComplianceLegalBasis,
  type CompliancePrivacyRequest,
  type CompliancePrivacyRequestAction,
  type CompliancePrivacyRequestDecision,
  type CompliancePrivacyRequestStatus,
  type CompliancePrivacyRequestType,
  type ComplianceRetentionAction,
  type ComplianceRetentionExecution,
  type ComplianceRetentionExecutionStatus,
  type ComplianceRetentionPolicy,
  type ComplianceRetentionPolicyStatus,
  type ComplianceRetentionTrigger,
  type ComplianceRiskLevel,
  type ComplianceSlaState,
  type ComplianceVendor,
  type ComplianceVendorRole,
  type ComplianceVendorStatus,
} from "./types.js";
import {
  assertComplianceId,
  cloneComplianceValue,
  complianceEntityId,
  normalizeComplianceLimit,
  normalizeComplianceTenantId,
  normalizeComplianceTimestamp,
  requireComplianceBoolean,
  requireComplianceCode,
  requireComplianceEnum,
  requireComplianceEnumList,
  requireComplianceEvidenceList,
  requireComplianceEvidenceOptionalList,
  requireComplianceIdentifier,
  requireComplianceInteger,
  requireCompliancePeriod,
  requireComplianceRegion,
  requireComplianceRegionList,
  requireComplianceResourceIdList,
  requireComplianceResponseDays,
  requireComplianceRetentionDays,
  requireComplianceStringList,
  requireComplianceSubjectRef,
  requireComplianceText,
  sortUnique,
} from "./validation.js";
import {
  assertComplianceReportIsRedacted,
  toComplianceAuditMetadata,
} from "./redaction.js";
import type {
  OpenPlatformDomainEventDescriptor,
  OpenPlatformEventPublisherPort,
  OpenPlatformOutboxRecord,
} from "../events.js";

export const COMPLIANCE_SYSTEM_ACTOR: ComplianceAuditActor = Object.freeze({
  type: "system",
  id: "compliance-service",
});

export interface ComplianceSlaPolicy {
  readonly policyCode: string;
  readonly defaultResponseDays: number;
  readonly responseDaysByType: Readonly<
    Partial<Record<CompliancePrivacyRequestType, number>>
  >;
}

export const COMPLIANCE_DEFAULT_SLA_POLICY: ComplianceSlaPolicy = Object.freeze({
  policyCode: COMPLIANCE_DEFAULT_SLA_POLICY_CODE,
  defaultResponseDays: 15,
  responseDaysByType: Object.freeze({}),
});

export function complianceResponseDaysFor(
  policy: ComplianceSlaPolicy,
  requestType: CompliancePrivacyRequestType,
): number {
  const configured = policy.responseDaysByType[requestType];
  if (configured === undefined) return policy.defaultResponseDays;
  return Math.min(
    Math.max(1, Math.trunc(configured)),
    COMPLIANCE_MAX_RESPONSE_DAYS,
  );
}

export interface ComplianceServiceOptions {
  readonly repositories?: InMemoryComplianceRepositories;
  readonly audit?: ComplianceAuditPort;
  readonly events?: ComplianceEventPort;
  readonly eventPublisher?: OpenPlatformEventPublisherPort;
  readonly eventsEnabled?: boolean;
  readonly clock?: () => Date;
  readonly idGenerator?: (kind: ComplianceEntityKind) => string;
  readonly slaPolicy?: ComplianceSlaPolicy;
  readonly production?: boolean;
}

export interface ComplianceActorContext {
  readonly actor?: ComplianceAuditActor;
  readonly requestId?: string;
  readonly idempotencyKey?: string;
}

export interface CreateDataAssetCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly name: string;
  readonly code: string;
  readonly classification: ComplianceDataClassificationInput;
  readonly categories: readonly ComplianceDataCategory[];
  readonly personalData: boolean;
  readonly sensitivePersonalData: boolean;
  readonly legalBasis?: ComplianceLegalBasis;
  readonly purposes?: readonly string[];
  readonly dataSubjects?: readonly ComplianceDataSubjectGroupInput[];
  readonly residencyRegions: readonly string[];
  readonly processorVendorId?: string;
  readonly retentionPolicyId?: string;
  readonly retentionDays?: number;
  readonly crossBorder: boolean;
  readonly evidence?: readonly ComplianceEvidence[];
}

export type ComplianceDataClassificationInput = ComplianceDataAsset["classification"];
export type ComplianceDataSubjectGroupInput = ComplianceDataAsset["dataSubjects"][number];

export interface UpdateDataAssetCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly name?: string;
  readonly classification?: ComplianceDataClassificationInput;
  readonly categories?: readonly ComplianceDataCategory[];
  readonly legalBasis?: ComplianceLegalBasis | null;
  readonly purposes?: readonly string[];
  readonly dataSubjects?: readonly ComplianceDataSubjectGroupInput[];
  readonly residencyRegions?: readonly string[];
  readonly processorVendorId?: string | null;
  readonly retentionPolicyId?: string | null;
  readonly retentionDays?: number | null;
  readonly crossBorder?: boolean;
  readonly evidence?: readonly ComplianceEvidence[];
}

export interface TransitionDataAssetCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly targetStatus: ComplianceDataAssetStatus;
}

export interface CreateConsentRecordCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly subjectRef: string;
  readonly subjectCount?: number;
  readonly purpose: string;
  readonly policyVersion: string;
  readonly channel: ComplianceConsentChannel;
  readonly language?: string;
  readonly scopes?: readonly string[];
  readonly dataAssetIds?: readonly string[];
  readonly expiresAt?: string;
  readonly status?: ComplianceConsentRecord["status"];
  readonly grantedAt?: string;
  readonly proof?: readonly ComplianceEvidence[];
}

export interface GrantConsentCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly grantedAt?: string;
  readonly proof: readonly ComplianceEvidence[];
  readonly expiresAt?: string;
}

export interface WithdrawConsentCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly withdrawnAt?: string;
  readonly reason?: string;
  readonly proof?: readonly ComplianceEvidence[];
}

export interface ExpireConsentCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
}

export interface CreatePrivacyRequestCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly requestType: CompliancePrivacyRequestType;
  readonly subjectRef: string;
  readonly subjectCount?: number;
  readonly dataAssetIds?: readonly string[];
  readonly receivedAt?: string;
  readonly responseDays?: number;
  readonly policyCode?: string;
  readonly duplicateOfId?: string;
}

export interface RecordIdentityVerificationCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly status: ComplianceIdentityVerificationStatus;
  readonly method?: ComplianceIdentityVerificationMethod;
  readonly verifiedByRef?: string;
  readonly evidence?: readonly ComplianceEvidence[];
}

export interface TransitionPrivacyRequestCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly targetStatus: CompliancePrivacyRequestStatus;
  readonly statusReason?: string;
}

export interface DecidePrivacyRequestCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly decision: CompliancePrivacyRequestDecision;
  readonly rationale?: string;
  readonly evidence: readonly ComplianceEvidence[];
  readonly targetStatus?: CompliancePrivacyRequestStatus;
}

export interface RecordPrivacyRequestActionCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly action: CompliancePrivacyRequestAction;
  readonly dataAssetId: string;
  readonly executedAt?: string;
  readonly affectedRecords?: number;
  readonly executionRef?: string;
}

export interface CreateRetentionPolicyCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly name: string;
  readonly code: string;
  readonly trigger: ComplianceRetentionTrigger;
  readonly action: ComplianceRetentionAction;
  readonly retentionDays: number;
  readonly requiresApproval: boolean;
  readonly legalHold: boolean;
  readonly dataAssetIds?: readonly string[];
  readonly residencyRegions?: readonly string[];
  readonly evidence?: readonly ComplianceEvidence[];
}

export interface TransitionRetentionPolicyCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly targetStatus: ComplianceRetentionPolicyStatus;
}

export interface RecordRetentionExecutionCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly policyId: string;
  readonly runId?: string;
  readonly dataAssetIds?: readonly string[];
  readonly status: ComplianceRetentionExecutionStatus;
  readonly action?: ComplianceRetentionAction;
  readonly occurredAt?: string;
  readonly blockedReason?: string;
  readonly recordsScanned?: number;
  readonly recordsDeleted?: number;
  readonly recordsAnonymized?: number;
  readonly recordsArchived?: number;
  readonly completedAt?: string;
  readonly failureReason?: string;
  readonly evidence?: readonly ComplianceEvidence[];
}

export interface CreateCrossBorderAssessmentCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly title: string;
  readonly code: string;
  readonly sourceRegion: string;
  readonly destinationRegions: readonly string[];
  readonly transferPurpose: string;
  readonly dataAssetIds?: readonly string[];
  readonly personalData?: boolean;
  readonly sensitivePersonalData?: boolean;
  readonly riskLevel?: ComplianceRiskLevel;
  readonly riskFactors?: readonly string[];
  readonly mechanisms?: readonly ComplianceCrossBorderMechanism[];
  readonly recipientVendorId?: string;
  readonly validUntil?: string;
  readonly evidence?: readonly ComplianceEvidence[];
}

export interface TransitionCrossBorderCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly targetStatus: ComplianceCrossBorderAssessment["status"];
  readonly riskLevel?: ComplianceRiskLevel;
  readonly riskFactors?: readonly string[];
  readonly mechanisms?: readonly ComplianceCrossBorderMechanism[];
  readonly evidence?: readonly ComplianceEvidence[];
  readonly validUntil?: string;
}

export interface CreateVendorCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly role: ComplianceVendorRole;
  readonly code: string;
  readonly legalName: string;
  readonly displayName?: string;
  readonly regions: readonly string[];
  readonly dataAssetIds?: readonly string[];
  readonly dataCategories?: readonly ComplianceDataCategory[];
  readonly parentVendorId?: string;
  readonly crossBorder?: boolean;
  readonly contractEffectiveAt?: string;
  readonly evidence?: readonly ComplianceEvidence[];
}

export interface TransitionVendorCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly targetStatus: ComplianceVendorStatus;
  readonly contractTerminatedAt?: string;
}

export interface RecordVendorAssessmentCommand extends ComplianceActorContext {
  readonly tenantId: string;
  readonly id: string;
  readonly status: ComplianceVendor["assessment"]["status"];
  readonly assessedByRef?: string;
  readonly evidence?: readonly ComplianceEvidence[];
}

export interface ComplianceListQuery {
  readonly tenantId: string;
  readonly status?: string;
  readonly ids?: readonly string[];
  readonly cursor?: string;
  readonly limit?: number | string;
}

export interface CompliancePage<T> {
  readonly items: readonly T[];
  readonly nextCursor?: string;
  readonly hasMore: boolean;
  readonly total: number;
}

export interface ComplianceSnapshot {
  readonly dataAssets: readonly ComplianceDataAsset[];
  readonly consentRecords: readonly ComplianceConsentRecord[];
  readonly privacyRequests: readonly CompliancePrivacyRequest[];
  readonly retentionPolicies: readonly ComplianceRetentionPolicy[];
  readonly retentionExecutions: readonly ComplianceRetentionExecution[];
  readonly crossBorderAssessments: readonly ComplianceCrossBorderAssessment[];
  readonly vendors: readonly ComplianceVendor[];
  readonly auditEvents: readonly ComplianceAuditRecord[];
}

export interface GenerateComplianceReportCommand {
  readonly tenantId: string;
  readonly from: string;
  readonly to: string;
  readonly generatedAt?: string;
}

export interface ComplianceSlaEvaluation {
  readonly state: ComplianceSlaState;
  readonly dueAt: string;
  readonly millisecondsRemaining: number;
}

type ComplianceAuditableRecord =
  | ComplianceDataAsset
  | ComplianceConsentRecord
  | CompliancePrivacyRequest
  | ComplianceRetentionPolicy
  | ComplianceRetentionExecution
  | ComplianceCrossBorderAssessment
  | ComplianceVendor;

export class ComplianceDomainService {
  readonly repositories: InMemoryComplianceRepositories;
  readonly audit: ComplianceAuditPort;
  readonly events: ComplianceEventPort;
  readonly eventPublisher: OpenPlatformEventPublisherPort | undefined;
  readonly eventReadiness: ComplianceDomainEventReadiness | undefined;
  readonly slaPolicy: ComplianceSlaPolicy;
  private readonly clock: () => Date;
  private readonly idGenerator: (kind: ComplianceEntityKind) => string;
  private readonly production: boolean;
  private readonly eventsEnabled: boolean;

  constructor(options: ComplianceServiceOptions = {}) {
    this.repositories =
      options.repositories ?? new InMemoryComplianceRepositories(options);
    this.audit =
      options.audit ??
      new InMemoryComplianceAuditStore({
        ...(options.clock === undefined ? {} : { clock: options.clock }),
        ...(options.production === undefined ? {} : { production: options.production }),
      });
    this.events = options.events ?? new InMemoryComplianceEventStore(options);
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator =
      options.idGenerator ??
      ((kind) => `${COMPLIANCE_ENTITY_PREFIXES[kind]}_${randomUUID()}`);
    this.slaPolicy = options.slaPolicy ?? COMPLIANCE_DEFAULT_SLA_POLICY;
    this.production = options.production === true;
    if (
      options.eventPublisher !== undefined &&
      !isComplianceEventPublisher(options.eventPublisher)
    ) {
      throw complianceValidationError(
        "Compliance event publisher is invalid",
        "eventPublisher",
      );
    }
    this.eventPublisher = options.eventPublisher;
    this.eventsEnabled =
      options.eventsEnabled === true && this.eventPublisher !== undefined;
    this.eventReadiness = complianceDomainEventPublisherReadiness(
      this.eventPublisher,
    );
  }

  async isReady(): Promise<boolean> {
    if (!this.repositories.readiness.ready()) return false;
    if (this.audit.readiness?.ready() === false) return false;
    return this.eventsOperationalReady();
  }

  async createDataAsset(command: CreateDataAssetCommand): Promise<ComplianceDataAsset> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const now = this.timestamp();
    const code = requireComplianceCode(command.code, "code");
    const existing = await this.repositories.dataAssets.findByCode(tenantId, code);
    if (existing !== undefined) {
      throw complianceResourceConflict("Compliance data asset code already exists");
    }
    const classification = requireComplianceEnum(
      command.classification,
      COMPLIANCE_DATA_CLASSIFICATIONS,
      "classification",
    );
    const categories = requireComplianceEnumList(
      command.categories,
      COMPLIANCE_DATA_CATEGORIES,
      "categories",
      { min: 1 },
    );
    const personalData = requireComplianceBoolean(command.personalData, "personalData");
    const sensitivePersonalData = requireComplianceBoolean(
      command.sensitivePersonalData,
      "sensitivePersonalData",
    );
    const legalBasis =
      command.legalBasis === undefined
        ? undefined
        : requireComplianceEnum(command.legalBasis, COMPLIANCE_LEGAL_BASES, "legalBasis");
    assertDataAssetClassification(
      classification,
      personalData,
      sensitivePersonalData,
      categories,
    );
    if (sensitivePersonalData && legalBasis === undefined) {
      throw complianceLegalBasisRequired();
    }
    const retentionPolicyId =
      command.retentionPolicyId === undefined
        ? undefined
        : assertComplianceId(
          command.retentionPolicyId,
          "retentionPolicy",
          "retentionPolicyId",
        );
    const retentionDays =
      command.retentionDays === undefined
        ? undefined
        : requireComplianceRetentionDays(command.retentionDays);
    if (retentionPolicyId !== undefined && retentionDays !== undefined) {
      throw complianceValidationError(
        "Compliance data asset must declare either a retention policy or retention days",
        "retentionPolicyId",
      );
    }
    if (retentionPolicyId !== undefined) {
      const policy = await this.repositories.retentionPolicies.get(
        tenantId,
        retentionPolicyId,
      );
      if (policy === undefined) throw complianceResourceNotFound("retentionPolicy");
    }
    const processorVendorId =
      command.processorVendorId === undefined
        ? undefined
        : assertComplianceId(command.processorVendorId, "vendor", "processorVendorId");
    if (processorVendorId !== undefined) {
      const vendor = await this.repositories.vendors.get(tenantId, processorVendorId);
      if (vendor === undefined) throw complianceResourceNotFound("vendor");
    }
    const record: ComplianceDataAsset = {
      id: this.nextId("dataAsset"),
      tenantId,
      kind: "dataAsset",
      version: 1,
      name: requireComplianceText(command.name, "name", 200),
      code,
      status: "draft",
      classification,
      categories,
      personalData,
      sensitivePersonalData,
      legalBasis,
      purposes: requireComplianceStringList(command.purposes ?? [], "purposes", { max: 16 }),
      dataSubjects: requireComplianceEnumList(
        command.dataSubjects ?? [],
        COMPLIANCE_DATA_SUBJECT_GROUPS,
        "dataSubjects",
      ),
      residencyRegions: requireComplianceRegionList(
        command.residencyRegions,
        "residencyRegions",
        { min: 1 },
      ),
      processorVendorId,
      retentionPolicyId,
      retentionDays,
      crossBorder: requireComplianceBoolean(command.crossBorder, "crossBorder"),
      evidence: requireComplianceEvidenceOptionalList(
        command.evidence,
        "evidence",
        COMPLIANCE_EVIDENCE_KINDS,
      ),
      createdAt: now,
      updatedAt: now,
    };
    await this.repositories.dataAssets.create(record);
    await this.record("dataAsset.create", record, command);
    return cloneComplianceValue(record);
  }

  async updateDataAsset(command: UpdateDataAssetCommand): Promise<ComplianceDataAsset> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.dataAssets.get(
      tenantId,
      assertComplianceId(command.id, "dataAsset"),
    );
    if (current === undefined) throw complianceResourceNotFound("dataAsset");
    const classification =
      command.classification === undefined
        ? current.classification
        : requireComplianceEnum(
          command.classification,
          COMPLIANCE_DATA_CLASSIFICATIONS,
          "classification",
        );
    const categories =
      command.categories === undefined
        ? current.categories
        : requireComplianceEnumList(
          command.categories,
          COMPLIANCE_DATA_CATEGORIES,
          "categories",
          { min: 1 },
        );
    const personalData = current.personalData;
    const sensitivePersonalData = current.sensitivePersonalData;
    const legalBasis =
      command.legalBasis === null
        ? undefined
        : command.legalBasis === undefined
          ? current.legalBasis
          : requireComplianceEnum(
            command.legalBasis,
            COMPLIANCE_LEGAL_BASES,
            "legalBasis",
          );
    assertDataAssetClassification(
      classification,
      personalData,
      sensitivePersonalData,
      categories,
    );
    if (sensitivePersonalData && legalBasis === undefined) {
      throw complianceLegalBasisRequired();
    }
    const retentionPolicyId =
      command.retentionPolicyId === null
        ? undefined
        : command.retentionPolicyId === undefined
          ? current.retentionPolicyId
          : assertComplianceId(
            command.retentionPolicyId,
            "retentionPolicy",
            "retentionPolicyId",
          );
    const retentionDays =
      command.retentionDays === null
        ? undefined
        : command.retentionDays === undefined
          ? current.retentionDays
          : requireComplianceRetentionDays(command.retentionDays);
    if (retentionPolicyId !== undefined && retentionDays !== undefined) {
      throw complianceValidationError(
        "Compliance data asset must declare either a retention policy or retention days",
        "retentionPolicyId",
      );
    }
    const processorVendorId =
      command.processorVendorId === null
        ? undefined
        : command.processorVendorId === undefined
          ? current.processorVendorId
          : assertComplianceId(
            command.processorVendorId,
            "vendor",
            "processorVendorId",
          );
    if (processorVendorId !== undefined) {
      const vendor = await this.repositories.vendors.get(tenantId, processorVendorId);
      if (vendor === undefined) throw complianceResourceNotFound("vendor");
    }
    const saved = await this.repositories.dataAssets.save({
      ...current,
      version: current.version + 1,
      name:
        command.name === undefined
          ? current.name
          : requireComplianceText(command.name, "name", 200),
      classification,
      categories: sortUnique(categories),
      legalBasis,
      purposes:
        command.purposes === undefined
          ? current.purposes
          : requireComplianceStringList(command.purposes, "purposes", { max: 16 }),
      dataSubjects:
        command.dataSubjects === undefined
          ? current.dataSubjects
          : requireComplianceEnumList(
            command.dataSubjects,
            COMPLIANCE_DATA_SUBJECT_GROUPS,
            "dataSubjects",
          ),
      residencyRegions:
        command.residencyRegions === undefined
          ? current.residencyRegions
          : requireComplianceRegionList(
            command.residencyRegions,
            "residencyRegions",
            { min: 1 },
          ),
      processorVendorId,
      retentionPolicyId,
      retentionDays,
      crossBorder:
        command.crossBorder === undefined
          ? current.crossBorder
          : requireComplianceBoolean(command.crossBorder, "crossBorder"),
      evidence:
        command.evidence === undefined
          ? current.evidence
          : requireComplianceEvidenceOptionalList(
            command.evidence,
            "evidence",
            COMPLIANCE_EVIDENCE_KINDS,
          ),
      updatedAt: this.timestamp(),
    });
    await this.record("dataAsset.transition", saved, command);
    return cloneComplianceValue(saved);
  }

  async transitionDataAsset(
    command: TransitionDataAssetCommand,
  ): Promise<ComplianceDataAsset> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.dataAssets.get(
      tenantId,
      assertComplianceId(command.id, "dataAsset"),
    );
    if (current === undefined) throw complianceResourceNotFound("dataAsset");
    const targetStatus = requireComplianceEnum(
      command.targetStatus,
      COMPLIANCE_DATA_ASSET_STATUSES,
      "targetStatus",
    );
    assertDataAssetTransition(current.status, targetStatus);
    if (targetStatus === "registered" || targetStatus === "active") {
      assertDataAssetClassification(
        current.classification,
        current.personalData,
        current.sensitivePersonalData,
        current.categories,
      );
      if (current.purposes.length === 0) {
        throw complianceValidationError(
          "Compliance data asset requires a declared purpose before registration",
          "purposes",
        );
      }
      if (current.sensitivePersonalData && current.legalBasis === undefined) {
        throw complianceLegalBasisRequired();
      }
      if (current.retentionPolicyId === undefined && current.retentionDays === undefined) {
        throw complianceValidationError(
          "Compliance data asset requires a retention policy or retention days",
          "retentionPolicyId",
        );
      }
    }
    const saved = await this.repositories.dataAssets.save({
      ...current,
      version: current.version + 1,
      status: targetStatus,
      updatedAt: this.timestamp(),
    });
    await this.record("dataAsset.transition", saved, command, {
      fromStatus: current.status,
      toStatus: targetStatus,
    });
    return cloneComplianceValue(saved);
  }

  async getDataAsset(
    tenantId: string,
    id: string,
  ): Promise<ComplianceDataAsset | undefined> {
    return this.repositories.dataAssets.get(
      normalizeComplianceTenantId(tenantId),
      assertComplianceId(id, "dataAsset"),
    );
  }

  async listDataAssets(
    query: ComplianceListQuery,
  ): Promise<CompliancePage<ComplianceDataAsset>> {
    return this.listRecords(
      query,
      (tenantId) => this.repositories.dataAssets.list(tenantId),
      (record) => record.status,
    );
  }

  async createConsentRecord(
    command: CreateConsentRecordCommand,
  ): Promise<ComplianceConsentRecord> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const now = this.timestamp();
    const status =
      command.status === undefined
        ? "pending"
        : requireComplianceEnum(
          command.status,
          COMPLIANCE_CONSENT_STATUSES,
          "status",
        );
    if (status === "withdrawn" || status === "expired") {
      throw complianceValidationError(
        "Compliance consent must be created as pending or granted",
        "status",
      );
    }
    const grantedAt =
      status === "granted"
        ? normalizeComplianceTimestamp(command.grantedAt ?? now, "grantedAt")
        : undefined;
    const proof = requireComplianceEvidenceList(
      command.proof ?? [],
      "proof",
      COMPLIANCE_EVIDENCE_KINDS,
      { min: status === "granted" ? 1 : 0 },
    );
    const record: ComplianceConsentRecord = {
      id: this.nextId("consentRecord"),
      tenantId,
      kind: "consentRecord",
      version: 1,
      status,
      subjectRef: requireComplianceSubjectRef(command.subjectRef),
      subjectCount: requireComplianceInteger(
        command.subjectCount ?? 1,
        "subjectCount",
        { min: 1, max: 1_000_000 },
      ),
      purpose: requireComplianceText(command.purpose, "purpose", 200),
      legalBasis: "consent",
      policyVersion: requireComplianceText(command.policyVersion, "policyVersion", 64),
      channel: requireComplianceEnum(
        command.channel,
        COMPLIANCE_CONSENT_CHANNELS,
        "channel",
      ),
      language:
        command.language === undefined
          ? undefined
          : requireComplianceText(command.language, "language", 32),
      scopes: requireComplianceStringList(command.scopes ?? [], "scopes", { max: 32 }),
      dataAssetIds: requireComplianceResourceIdList(
        command.dataAssetIds ?? [],
        "dataAsset",
        "dataAssetIds",
        { allowEmpty: true },
      ),
      grantedAt,
      expiresAt:
        command.expiresAt === undefined
          ? undefined
          : normalizeComplianceTimestamp(command.expiresAt, "expiresAt"),
      proof,
      createdAt: now,
      updatedAt: now,
    };
    if (record.expiresAt !== undefined && record.grantedAt !== undefined) {
      if (Date.parse(record.expiresAt) <= Date.parse(record.grantedAt)) {
        throw complianceValidationError(
          "Compliance consent expiry must be after the grant time",
          "expiresAt",
        );
      }
    }
    await this.repositories.consentRecords.create(record);
    await this.record("consentRecord.create", record, command);
    if (status === "granted") {
      await this.record("consentRecord.grant", record, command, {
        toStatus: "granted",
      });
    }
    return cloneComplianceValue(record);
  }

  async grantConsent(command: GrantConsentCommand): Promise<ComplianceConsentRecord> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.consentRecords.get(
      tenantId,
      assertComplianceId(command.id, "consentRecord"),
    );
    if (current === undefined) throw complianceResourceNotFound("consentRecord");
    assertConsentTransition(current.status, "granted");
    const proof = requireComplianceEvidenceList(
      command.proof,
      "proof",
      COMPLIANCE_EVIDENCE_KINDS,
      { min: 1 },
    );
    const grantedAt = normalizeComplianceTimestamp(
      command.grantedAt ?? this.timestamp(),
      "grantedAt",
    );
    const expiresAt =
      command.expiresAt === undefined
        ? current.expiresAt
        : normalizeComplianceTimestamp(command.expiresAt, "expiresAt");
    if (expiresAt !== undefined && Date.parse(expiresAt) <= Date.parse(grantedAt)) {
      throw complianceValidationError(
        "Compliance consent expiry must be after the grant time",
        "expiresAt",
      );
    }
    const saved = await this.repositories.consentRecords.save({
      ...current,
      version: current.version + 1,
      status: "granted",
      grantedAt,
      expiresAt,
      proof: sortEvidence([...current.proof, ...proof]),
      updatedAt: this.timestamp(),
    });
    await this.record("consentRecord.grant", saved, command, {
      fromStatus: current.status,
      toStatus: "granted",
    });
    return cloneComplianceValue(saved);
  }

  async withdrawConsent(
    command: WithdrawConsentCommand,
  ): Promise<ComplianceConsentRecord> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.consentRecords.get(
      tenantId,
      assertComplianceId(command.id, "consentRecord"),
    );
    if (current === undefined) throw complianceResourceNotFound("consentRecord");
    assertConsentTransition(current.status, "withdrawn");
    const withdrawnAt = normalizeComplianceTimestamp(
      command.withdrawnAt ?? this.timestamp(),
      "withdrawnAt",
    );
    const proof = requireComplianceEvidenceOptionalList(
      command.proof,
      "proof",
      COMPLIANCE_EVIDENCE_KINDS,
    );
    const saved = await this.repositories.consentRecords.save({
      ...current,
      version: current.version + 1,
      status: "withdrawn",
      withdrawnAt,
      withdrawalReason:
        command.reason === undefined
          ? undefined
          : requireComplianceText(command.reason, "reason", 512),
      proof: sortEvidence([...current.proof, ...proof]),
      updatedAt: this.timestamp(),
    });
    await this.record("consentRecord.withdraw", saved, command, {
      fromStatus: current.status,
      toStatus: "withdrawn",
    });
    return cloneComplianceValue(saved);
  }

  async expireConsent(command: ExpireConsentCommand): Promise<ComplianceConsentRecord> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.consentRecords.get(
      tenantId,
      assertComplianceId(command.id, "consentRecord"),
    );
    if (current === undefined) throw complianceResourceNotFound("consentRecord");
    assertConsentTransition(current.status, "expired");
    const saved = await this.repositories.consentRecords.save({
      ...current,
      version: current.version + 1,
      status: "expired",
      updatedAt: this.timestamp(),
    });
    await this.record("consentRecord.transition", saved, command, {
      fromStatus: current.status,
      toStatus: "expired",
    });
    return cloneComplianceValue(saved);
  }

  async getConsentRecord(
    tenantId: string,
    id: string,
  ): Promise<ComplianceConsentRecord | undefined> {
    return this.repositories.consentRecords.get(
      normalizeComplianceTenantId(tenantId),
      assertComplianceId(id, "consentRecord"),
    );
  }

  async listConsentRecords(
    query: ComplianceListQuery,
  ): Promise<CompliancePage<ComplianceConsentRecord>> {
    return this.listRecords(
      query,
      (tenantId) => this.repositories.consentRecords.list(tenantId),
      (record) => record.status,
    );
  }

  async findActiveConsent(
    tenantId: string,
    subjectRef: string,
    purpose: string,
  ): Promise<ComplianceConsentRecord | undefined> {
    return this.repositories.consentRecords.findActive(
      normalizeComplianceTenantId(tenantId),
      requireComplianceSubjectRef(subjectRef),
      requireComplianceText(purpose, "purpose", 200),
    );
  }

  async createPrivacyRequest(
    command: CreatePrivacyRequestCommand,
  ): Promise<CompliancePrivacyRequest> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const now = this.timestamp();
    const requestType = requireComplianceEnum(
      command.requestType,
      COMPLIANCE_PRIVACY_REQUEST_TYPES,
      "requestType",
    );
    const dataAssetIds = requireComplianceResourceIdList(
      command.dataAssetIds ?? [],
      "dataAsset",
      "dataAssetIds",
      { allowEmpty: true },
    );
    await this.assertDataAssetsInTenant(tenantId, dataAssetIds);
    const receivedAt = normalizeComplianceTimestamp(
      command.receivedAt ?? now,
      "receivedAt",
    );
    const responseDays = requireComplianceResponseDays(
      command.responseDays ??
        complianceResponseDaysFor(this.slaPolicy, requestType),
    );
    const policyCode =
      command.policyCode === undefined
        ? this.slaPolicy.policyCode
        : requireComplianceText(command.policyCode, "policyCode", 64);
    if (command.duplicateOfId !== undefined) {
      const duplicateOfId = assertComplianceId(
        command.duplicateOfId,
        "privacyRequest",
        "duplicateOfId",
      );
      const original = await this.repositories.privacyRequests.get(
        tenantId,
        duplicateOfId,
      );
      if (original === undefined) {
        throw complianceValidationError(
          "Compliance duplicate reference is unknown",
          "duplicateOfId",
        );
      }
    }
    const dueAt = new Date(
      Date.parse(receivedAt) + responseDays * 86_400_000,
    ).toISOString();
    const record: CompliancePrivacyRequest = {
      id: this.nextId("privacyRequest"),
      tenantId,
      kind: "privacyRequest",
      version: 1,
      requestType,
      status: "submitted",
      statusReason: undefined,
      subjectRef: requireComplianceSubjectRef(command.subjectRef),
      subjectCount: requireComplianceInteger(
        command.subjectCount ?? 1,
        "subjectCount",
        { min: 1, max: 1_000_000 },
      ),
      dataAssetIds,
      identityVerification: {
        status: "notStarted",
        attempts: 0,
        evidence: [],
      },
      sla: {
        policyCode,
        responseDays,
        dueAt,
        respondedAt: undefined,
        closedAt: undefined,
        state: this.openSla(dueAt, receivedAt).state,
      },
      decision: undefined,
      actions: [],
      duplicateOfId: command.duplicateOfId === undefined
        ? undefined
        : assertComplianceId(
          command.duplicateOfId,
          "privacyRequest",
          "duplicateOfId",
        ),
      createdAt: receivedAt,
      updatedAt: receivedAt,
    };
    await this.repositories.privacyRequests.create(record);
    await this.record("privacyRequest.create", record, command);
    return cloneComplianceValue(record);
  }

  async recordIdentityVerification(
    command: RecordIdentityVerificationCommand,
  ): Promise<CompliancePrivacyRequest> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.privacyRequests.get(
      tenantId,
      assertComplianceId(command.id, "privacyRequest"),
    );
    if (current === undefined) throw complianceResourceNotFound("privacyRequest");
    const status = requireComplianceEnum(
      command.status,
      COMPLIANCE_IDENTITY_VERIFICATION_STATUSES,
      "status",
    );
    const evidence = requireComplianceEvidenceOptionalList(
      command.evidence,
      "evidence",
      COMPLIANCE_EVIDENCE_KINDS,
      { min: status === "verified" ? 1 : 0 },
    );
    const method =
      command.method === undefined
        ? undefined
        : requireComplianceEnum(
          command.method,
          COMPLIANCE_IDENTITY_VERIFICATION_METHODS,
          "method",
        );
    if (status === "verified" && method === undefined) {
      throw complianceIdentityVerificationRequired("method");
    }
    if (isPrivacyRequestTerminalStatus(current.status) && status !== "verified") {
      throw complianceResourceConflict(
        "Compliance privacy request identity state is frozen after closure",
      );
    }
    const verificationStatus = nextIdentityStatus(
      current.identityVerification.status,
      status,
    );
    const now = this.timestamp();
    const saved = await this.repositories.privacyRequests.save({
      ...current,
      version: current.version + 1,
      identityVerification: {
        status: verificationStatus,
        method: method ?? current.identityVerification.method,
        attempts: current.identityVerification.attempts + 1,
        verifiedAt:
          verificationStatus === "verified"
            ? current.identityVerification.verifiedAt ?? now
            : current.identityVerification.verifiedAt,
        verifiedByRef:
          verificationStatus === "verified"
            ? requireComplianceIdentifier(
              command.verifiedByRef ?? this.actorRef(command),
              "verifiedByRef",
            )
            : current.identityVerification.verifiedByRef,
        evidence: sortEvidence([
          ...current.identityVerification.evidence,
          ...evidence,
        ]),
      },
      updatedAt: now,
    });
    await this.record("privacyRequest.verifyIdentity", saved, command, {
      toStatus: verificationStatus,
    });
    return cloneComplianceValue(saved);
  }

  async transitionPrivacyRequest(
    command: TransitionPrivacyRequestCommand,
  ): Promise<CompliancePrivacyRequest> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.privacyRequests.get(
      tenantId,
      assertComplianceId(command.id, "privacyRequest"),
    );
    if (current === undefined) throw complianceResourceNotFound("privacyRequest");
    const targetStatus = requireComplianceEnum(
      command.targetStatus,
      COMPLIANCE_PRIVACY_REQUEST_STATUSES,
      "targetStatus",
    );
    assertPrivacyRequestTransition(current.status, targetStatus);
    if (
      privacyRequestRequiresIdentityVerification(targetStatus) &&
      current.identityVerification.status !== "verified"
    ) {
      throw complianceIdentityVerificationRequired();
    }
    if (privacyRequestRequiresDecision(targetStatus) && current.decision === undefined) {
      throw complianceValidationError(
        "Compliance privacy request requires a recorded decision",
        "decision",
      );
    }
    if (targetStatus === "rejected" && current.decision?.decision !== "denied") {
      throw complianceValidationError(
        "Compliance privacy request rejection requires a denied decision",
        "decision",
      );
    }
    if (targetStatus === "fulfilled" && current.actions.length === 0) {
      throw complianceValidationError(
        "Compliance privacy request fulfilment requires a recorded action",
        "actions",
      );
    }
    const now = this.timestamp();
    const saved = await this.repositories.privacyRequests.save({
      ...current,
      version: current.version + 1,
      status: targetStatus,
      statusReason:
        command.statusReason === undefined
          ? undefined
          : requireComplianceText(command.statusReason, "statusReason", 512),
      sla: this.closeSla(current, now, isPrivacyRequestTerminalStatus(targetStatus)),
      updatedAt: now,
    });
    await this.record("privacyRequest.transition", saved, command, {
      fromStatus: current.status,
      toStatus: targetStatus,
    });
    return cloneComplianceValue(saved);
  }

  async decidePrivacyRequest(
    command: DecidePrivacyRequestCommand,
  ): Promise<CompliancePrivacyRequest> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.privacyRequests.get(
      tenantId,
      assertComplianceId(command.id, "privacyRequest"),
    );
    if (current === undefined) throw complianceResourceNotFound("privacyRequest");
    if (current.identityVerification.status !== "verified") {
      throw complianceIdentityVerificationRequired();
    }
    const decision = requireComplianceEnum(
      command.decision,
      COMPLIANCE_PRIVACY_REQUEST_DECISIONS,
      "decision",
    );
    const evidence = requireComplianceEvidenceList(
      command.evidence,
      "evidence",
      COMPLIANCE_EVIDENCE_KINDS,
      { min: 1 },
    );
    const targetStatus =
      command.targetStatus ??
      (decision === "denied" ? "rejected" : "inProgress");
    assertPrivacyRequestTransition(current.status, targetStatus);
    const now = this.timestamp();
    const saved = await this.repositories.privacyRequests.save({
      ...current,
      version: current.version + 1,
      status: targetStatus,
      decision: {
        decision,
        decidedAt: now,
        decidedByRef: requireComplianceIdentifier(
          command.actor?.id ?? this.actorRef(command),
          "decidedByRef",
        ),
        rationale:
          command.rationale === undefined
            ? undefined
            : requireComplianceText(command.rationale, "rationale", 1024),
        evidence,
      },
      sla: this.closeSla(current, now, isPrivacyRequestTerminalStatus(targetStatus)),
      updatedAt: now,
    });
    await this.record("privacyRequest.decide", saved, command, {
      fromStatus: current.status,
      toStatus: targetStatus,
    });
    return cloneComplianceValue(saved);
  }

  async recordPrivacyRequestAction(
    command: RecordPrivacyRequestActionCommand,
  ): Promise<CompliancePrivacyRequest> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.privacyRequests.get(
      tenantId,
      assertComplianceId(command.id, "privacyRequest"),
    );
    if (current === undefined) throw complianceResourceNotFound("privacyRequest");
    if (isPrivacyRequestTerminalStatus(current.status)) {
      throw complianceResourceConflict("Compliance privacy request is already closed");
    }
    if (current.identityVerification.status !== "verified") {
      throw complianceIdentityVerificationRequired();
    }
    const action = requireComplianceEnum(
      command.action,
      COMPLIANCE_PRIVACY_REQUEST_ACTIONS,
      "action",
    );
    const dataAssetId = assertComplianceId(
      command.dataAssetId,
      "dataAsset",
      "dataAssetId",
    );
    if (
      current.dataAssetIds.length > 0 &&
      !current.dataAssetIds.includes(dataAssetId)
    ) {
      throw complianceValidationError(
        "Compliance privacy request action is outside the declared asset scope",
        "dataAssetId",
      );
    }
    const executedAt = normalizeComplianceTimestamp(
      command.executedAt ?? this.timestamp(),
      "executedAt",
    );
    const affectedRecords =
      command.affectedRecords === undefined
        ? undefined
        : requireComplianceInteger(command.affectedRecords, "affectedRecords", {
          min: 0,
        });
    const executionRef =
      command.executionRef === undefined
        ? undefined
        : requireComplianceIdentifier(command.executionRef, "executionRef", 256);
    const saved = await this.repositories.privacyRequests.save({
      ...current,
      version: current.version + 1,
      actions: [
        ...current.actions,
        { action, dataAssetId, executedAt, affectedRecords, executionRef },
      ],
      updatedAt: this.timestamp(),
    });
    await this.record("privacyRequest.recordAction", saved, command, {
      toStatus: action,
    });
    return cloneComplianceValue(saved);
  }

  async getPrivacyRequest(
    tenantId: string,
    id: string,
  ): Promise<CompliancePrivacyRequest | undefined> {
    return this.repositories.privacyRequests.get(
      normalizeComplianceTenantId(tenantId),
      assertComplianceId(id, "privacyRequest"),
    );
  }

  async listPrivacyRequests(
    query: ComplianceListQuery,
  ): Promise<CompliancePage<CompliancePrivacyRequest>> {
    return this.listRecords(
      query,
      (tenantId) => this.repositories.privacyRequests.list(tenantId),
      (record) => record.status,
    );
  }

  async evaluatePrivacyRequestSla(
    tenantId: string,
    id: string,
    at?: string,
  ): Promise<ComplianceSlaEvaluation> {
    const record = await this.getPrivacyRequest(tenantId, id);
    if (record === undefined) throw complianceResourceNotFound("privacyRequest");
    const point = normalizeComplianceTimestamp(at ?? this.timestamp(), "at");
    if (isPrivacyRequestTerminalStatus(record.status)) {
      return {
        state: record.sla.state,
        dueAt: record.sla.dueAt,
        millisecondsRemaining:
          Date.parse(record.sla.dueAt) - Date.parse(point),
      };
    }
    return this.openSla(record.sla.dueAt, point);
  }

  async createRetentionPolicy(
    command: CreateRetentionPolicyCommand,
  ): Promise<ComplianceRetentionPolicy> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const now = this.timestamp();
    const code = requireComplianceCode(command.code, "code");
    const existing = await this.repositories.retentionPolicies.findByCode(tenantId, code);
    if (existing !== undefined) {
      throw complianceResourceConflict(
        "Compliance retention policy code already exists",
      );
    }
    const dataAssetIds = requireComplianceResourceIdList(
      command.dataAssetIds ?? [],
      "dataAsset",
      "dataAssetIds",
      { allowEmpty: true },
    );
    await this.assertDataAssetsInTenant(tenantId, dataAssetIds);
    const record: ComplianceRetentionPolicy = {
      id: this.nextId("retentionPolicy"),
      tenantId,
      kind: "retentionPolicy",
      version: 1,
      name: requireComplianceText(command.name, "name", 200),
      code,
      status: "draft",
      trigger: requireComplianceEnum(
        command.trigger,
        COMPLIANCE_RETENTION_TRIGGERS,
        "trigger",
      ),
      action: requireComplianceEnum(
        command.action,
        COMPLIANCE_RETENTION_ACTIONS,
        "action",
      ),
      retentionDays: requireComplianceRetentionDays(command.retentionDays),
      requiresApproval: requireComplianceBoolean(
        command.requiresApproval,
        "requiresApproval",
      ),
      legalHold: requireComplianceBoolean(command.legalHold, "legalHold"),
      dataAssetIds,
      residencyRegions: requireComplianceRegionList(
        command.residencyRegions ?? [],
        "residencyRegions",
      ),
      evidence: requireComplianceEvidenceOptionalList(
        command.evidence,
        "evidence",
        COMPLIANCE_EVIDENCE_KINDS,
      ),
      createdAt: now,
      updatedAt: now,
    };
    await this.repositories.retentionPolicies.create(record);
    await this.record("retentionPolicy.create", record, command);
    return cloneComplianceValue(record);
  }

  async transitionRetentionPolicy(
    command: TransitionRetentionPolicyCommand,
  ): Promise<ComplianceRetentionPolicy> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.retentionPolicies.get(
      tenantId,
      assertComplianceId(command.id, "retentionPolicy"),
    );
    if (current === undefined) throw complianceResourceNotFound("retentionPolicy");
    const targetStatus = requireComplianceEnum(
      command.targetStatus,
      COMPLIANCE_RETENTION_POLICY_STATUSES,
      "targetStatus",
    );
    assertRetentionPolicyTransition(current.status, targetStatus);
    if (targetStatus === "active" && current.evidence.length === 0) {
      throw complianceValidationError(
        "Compliance retention policy requires evidence before activation",
        "evidence",
      );
    }
    if (targetStatus === "superseded") {
      const successors = (
        await this.repositories.retentionPolicies.list(tenantId)
      ).filter((policy) => policy.status === "active" && policy.id !== current.id);
      if (successors.length === 0) {
        throw complianceResourceConflict(
          "Compliance retention policy has no active successor to take over",
        );
      }
    }
    const saved = await this.repositories.retentionPolicies.save({
      ...current,
      version: current.version + 1,
      status: targetStatus,
      updatedAt: this.timestamp(),
    });
    await this.record("retentionPolicy.transition", saved, command, {
      fromStatus: current.status,
      toStatus: targetStatus,
    });
    return cloneComplianceValue(saved);
  }

  async recordRetentionExecution(
    command: RecordRetentionExecutionCommand,
  ): Promise<ComplianceRetentionExecution> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const policyId = assertComplianceId(
      command.policyId,
      "retentionPolicy",
      "policyId",
    );
    const policy = await this.repositories.retentionPolicies.get(tenantId, policyId);
    if (policy === undefined) throw complianceResourceNotFound("retentionPolicy");
    const status = requireComplianceEnum(
      command.status,
      COMPLIANCE_RETENTION_EXECUTION_STATUSES,
      "status",
    );
    if (status !== "blocked" && status !== "skipped" && policy.status !== "active") {
      throw complianceResourceConflict(
        "Compliance retention policy must be active before execution",
      );
    }
    if ((status === "blocked" || status === "skipped") && policy.legalHold) {
      throw complianceResourceConflict(
        "Compliance retention policy is under legal hold",
      );
    }
    if (
      (status === "completed" || status === "failed") &&
      policy.requiresApproval
    ) {
      throw complianceResourceConflict(
        "Compliance retention policy requires an approval record before finalization",
      );
    }
    const dataAssetIds = sortUnique(
      command.dataAssetIds === undefined
        ? [...policy.dataAssetIds]
        : requireComplianceResourceIdList(
          command.dataAssetIds,
          "dataAsset",
          "dataAssetIds",
          { allowEmpty: true },
        ),
    );
    await this.assertDataAssetsInTenant(tenantId, dataAssetIds);
    const runId = requireComplianceIdentifier(
      command.runId ?? `run_${randomUUID()}`,
      "runId",
      128,
    );
    const finalized = (
      await this.repositories.retentionExecutions.listByRun(tenantId, runId)
    ).some(
      (execution) =>
        execution.status === "completed" ||
        execution.status === "failed",
    );
    if (finalized) {
      throw complianceResourceConflict(
        "Compliance retention run is already finalized",
      );
    }
    const occurredAt = normalizeComplianceTimestamp(
      command.occurredAt ?? this.timestamp(),
      "occurredAt",
    );
    const completedAt =
      status === "completed"
        ? normalizeComplianceTimestamp(
          command.completedAt ?? this.timestamp(),
          "completedAt",
        )
        : undefined;
    const record: ComplianceRetentionExecution = {
      id: this.nextId("retentionExecution"),
      tenantId,
      kind: "retentionExecution",
      version: 1,
      policyId,
      dataAssetIds,
      status,
      action:
        command.action === undefined
          ? policy.action
          : requireComplianceEnum(
            command.action,
            COMPLIANCE_RETENTION_ACTIONS,
            "action",
          ),
      runId,
      blockedReason:
        command.blockedReason === undefined
          ? undefined
          : requireComplianceText(command.blockedReason, "blockedReason", 512),
      result: {
        recordsScanned: requireComplianceInteger(
          command.recordsScanned ?? 0,
          "recordsScanned",
          { min: 0 },
        ),
        recordsDeleted: requireComplianceInteger(
          command.recordsDeleted ?? 0,
          "recordsDeleted",
          { min: 0 },
        ),
        recordsAnonymized: requireComplianceInteger(
          command.recordsAnonymized ?? 0,
          "recordsAnonymized",
          { min: 0 },
        ),
        recordsArchived: requireComplianceInteger(
          command.recordsArchived ?? 0,
          "recordsArchived",
          { min: 0 },
        ),
        completedAt,
        failureReason:
          command.failureReason === undefined
            ? undefined
            : requireComplianceText(command.failureReason, "failureReason", 512),
        evidence: requireComplianceEvidenceOptionalList(
          command.evidence,
          "evidence",
          COMPLIANCE_EVIDENCE_KINDS,
        ),
      },
      recordedByRef: this.actorRef(command),
      occurredAt,
      createdAt: occurredAt,
      updatedAt: occurredAt,
    };
    const saved = await this.repositories.retentionExecutions.appendExecution(record);
    const latest = await this.repositories.retentionPolicies.get(tenantId, policyId);
    const policyVersion = policy.version + 1;
    if (latest !== undefined) {
      await this.repositories.retentionPolicies.save({
        ...latest,
        version: latest.version + 1,
        lastExecutionId: saved.id,
        updatedAt: this.timestamp(),
      });
    }
    await this.record(
      "retentionExecution.record",
      saved,
      command,
      { toStatus: status },
      { id: policy.id, version: policyVersion, status: latest?.status ?? policy.status },
    );
    return cloneComplianceValue(saved);
  }

  async getRetentionPolicy(
    tenantId: string,
    id: string,
  ): Promise<ComplianceRetentionPolicy | undefined> {
    return this.repositories.retentionPolicies.get(
      normalizeComplianceTenantId(tenantId),
      assertComplianceId(id, "retentionPolicy"),
    );
  }

  async listRetentionPolicies(
    query: ComplianceListQuery,
  ): Promise<CompliancePage<ComplianceRetentionPolicy>> {
    return this.listRecords(
      query,
      (tenantId) => this.repositories.retentionPolicies.list(tenantId),
      (record) => record.status,
    );
  }

  async listRetentionExecutions(
    query: ComplianceListQuery,
  ): Promise<CompliancePage<ComplianceRetentionExecution>> {
    return this.listRecords(
      query,
      (tenantId) => this.repositories.retentionExecutions.list(tenantId),
      (record) => record.status,
    );
  }

  async createCrossBorderAssessment(
    command: CreateCrossBorderAssessmentCommand,
  ): Promise<ComplianceCrossBorderAssessment> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const now = this.timestamp();
    const code = requireComplianceCode(command.code, "code");
    const existing = await this.repositories.crossBorderAssessments.findByCode(
      tenantId,
      code,
    );
    if (existing !== undefined) {
      throw complianceResourceConflict(
        "Compliance cross-border assessment code already exists",
      );
    }
    const dataAssetIds = requireComplianceResourceIdList(
      command.dataAssetIds ?? [],
      "dataAsset",
      "dataAssetIds",
      { allowEmpty: true },
    );
    await this.assertDataAssetsInTenant(tenantId, dataAssetIds);
    const personalData = requireComplianceBoolean(
      command.personalData ?? dataAssetIds.length > 0,
      "personalData",
    );
    const sensitivePersonalData = requireComplianceBoolean(
      command.sensitivePersonalData ?? false,
      "sensitivePersonalData",
    );
    if (sensitivePersonalData && !personalData) {
      throw complianceValidationError(
        "Compliance cross-border assessment cannot declare sensitive data without personal data",
        "sensitivePersonalData",
      );
    }
    const recipientVendorId =
      command.recipientVendorId === undefined
        ? undefined
        : assertComplianceId(
          command.recipientVendorId,
          "vendor",
          "recipientVendorId",
        );
    if (recipientVendorId !== undefined) {
      const vendor = await this.repositories.vendors.get(tenantId, recipientVendorId);
      if (vendor === undefined) throw complianceResourceNotFound("vendor");
    }
    const record: ComplianceCrossBorderAssessment = {
      id: this.nextId("crossBorderAssessment"),
      tenantId,
      kind: "crossBorderAssessment",
      version: 1,
      title: requireComplianceText(command.title, "title", 200),
      code,
      status: "draft",
      sourceRegion: requireComplianceRegion(command.sourceRegion, "sourceRegion"),
      destinationRegions: requireComplianceRegionList(
        command.destinationRegions,
        "destinationRegions",
        { min: 1 },
      ),
      transferPurpose: requireComplianceText(
        command.transferPurpose,
        "transferPurpose",
        512,
      ),
      dataAssetIds,
      personalData,
      sensitivePersonalData,
      riskLevel: requireComplianceEnum(
        command.riskLevel ?? defaultRiskLevel(personalData, sensitivePersonalData),
        COMPLIANCE_RISK_LEVELS,
        "riskLevel",
      ),
      riskFactors: requireComplianceStringList(
        command.riskFactors ?? [],
        "riskFactors",
        { max: 16 },
      ),
      mechanisms: requireComplianceEnumList(
        command.mechanisms ?? [],
        COMPLIANCE_CROSS_BORDER_MECHANISMS,
        "mechanisms",
      ),
      recipientVendorId,
      decidedAt: undefined,
      decidedByRef: undefined,
      validUntil:
        command.validUntil === undefined
          ? undefined
          : normalizeComplianceTimestamp(command.validUntil, "validUntil"),
      evidence: requireComplianceEvidenceOptionalList(
        command.evidence,
        "evidence",
        COMPLIANCE_EVIDENCE_KINDS,
      ),
      createdAt: now,
      updatedAt: now,
    };
    await this.repositories.crossBorderAssessments.create(record);
    await this.record("crossBorderAssessment.create", record, command);
    return cloneComplianceValue(record);
  }

  async transitionCrossBorderAssessment(
    command: TransitionCrossBorderCommand,
  ): Promise<ComplianceCrossBorderAssessment> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.crossBorderAssessments.get(
      tenantId,
      assertComplianceId(command.id, "crossBorderAssessment"),
    );
    if (current === undefined) throw complianceResourceNotFound("crossBorderAssessment");
    const targetStatus = requireComplianceEnum(
      command.targetStatus,
      COMPLIANCE_CROSS_BORDER_STATUSES,
      "targetStatus",
    );
    assertCrossBorderTransition(current.status, targetStatus);
    const mechanisms =
      command.mechanisms === undefined
        ? current.mechanisms
        : requireComplianceEnumList(
          command.mechanisms,
          COMPLIANCE_CROSS_BORDER_MECHANISMS,
          "mechanisms",
        );
    const evidence =
      command.evidence === undefined
        ? current.evidence
        : requireComplianceEvidenceOptionalList(
          command.evidence,
          "evidence",
          COMPLIANCE_EVIDENCE_KINDS,
        );
    const carriesData = current.personalData || current.sensitivePersonalData;
    if (carriesData && mechanisms.length === 0) {
      if (
        targetStatus === "pendingApproval" ||
        targetStatus === "approved" ||
        targetStatus === "rejected"
      ) {
        throw complianceCrossBorderMechanismRequired();
      }
    }
    const isDecision = targetStatus === "approved" || targetStatus === "rejected";
    if (
      isDecision &&
      current.evidence.length === 0 &&
      evidence.length === 0
    ) {
      throw complianceValidationError(
        "Compliance cross-border decision requires evidence references",
        "evidence",
      );
    }
    const now = this.timestamp();
    const saved = await this.repositories.crossBorderAssessments.save({
      ...current,
      version: current.version + 1,
      status: targetStatus,
      riskLevel:
        command.riskLevel === undefined
          ? current.riskLevel
          : requireComplianceEnum(
            command.riskLevel,
            COMPLIANCE_RISK_LEVELS,
            "riskLevel",
          ),
      riskFactors:
        command.riskFactors === undefined
          ? current.riskFactors
          : requireComplianceStringList(command.riskFactors, "riskFactors", {
            max: 16,
          }),
      mechanisms,
      evidence: sortEvidence([...current.evidence, ...evidence]),
      decidedAt: isDecision ? now : current.decidedAt,
      decidedByRef: isDecision
        ? requireComplianceIdentifier(this.actorRef(command), "decidedByRef")
        : current.decidedByRef,
      validUntil:
        command.validUntil === undefined
          ? current.validUntil
          : normalizeComplianceTimestamp(command.validUntil, "validUntil"),
      updatedAt: now,
    });
    await this.record(
      isDecision
        ? "crossBorderAssessment.decide"
        : "crossBorderAssessment.transition",
      saved,
      command,
      { fromStatus: current.status, toStatus: targetStatus },
    );
    return cloneComplianceValue(saved);
  }

  async getCrossBorderAssessment(
    tenantId: string,
    id: string,
  ): Promise<ComplianceCrossBorderAssessment | undefined> {
    return this.repositories.crossBorderAssessments.get(
      normalizeComplianceTenantId(tenantId),
      assertComplianceId(id, "crossBorderAssessment"),
    );
  }

  async listCrossBorderAssessments(
    query: ComplianceListQuery,
  ): Promise<CompliancePage<ComplianceCrossBorderAssessment>> {
    return this.listRecords(
      query,
      (tenantId) => this.repositories.crossBorderAssessments.list(tenantId),
      (record) => record.status,
    );
  }

  async createVendor(command: CreateVendorCommand): Promise<ComplianceVendor> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const now = this.timestamp();
    const code = requireComplianceCode(command.code, "code");
    const existing = await this.repositories.vendors.findByCode(tenantId, code);
    if (existing !== undefined) {
      throw complianceResourceConflict("Compliance vendor code already exists");
    }
    const role = requireComplianceEnum(command.role, COMPLIANCE_VENDOR_ROLES, "role");
    const parentVendorId =
      command.parentVendorId === undefined
        ? undefined
        : assertComplianceId(command.parentVendorId, "vendor", "parentVendorId");
    if (role === "subProcessor" && parentVendorId === undefined) {
      throw complianceValidationError(
        "Compliance sub-processor requires a parent processor reference",
        "parentVendorId",
      );
    }
    if (parentVendorId !== undefined) {
      const parent = await this.repositories.vendors.get(tenantId, parentVendorId);
      if (parent === undefined) throw complianceResourceNotFound("vendor");
      if (parent.role !== "processor") {
        throw complianceValidationError(
          "Compliance sub-processor parent must be a processor",
          "parentVendorId",
        );
      }
    }
    const dataAssetIds = requireComplianceResourceIdList(
      command.dataAssetIds ?? [],
      "dataAsset",
      "dataAssetIds",
      { allowEmpty: true },
    );
    await this.assertDataAssetsInTenant(tenantId, dataAssetIds);
    const regions = requireComplianceRegionList(command.regions, "regions", { min: 1 });
    const record: ComplianceVendor = {
      id: this.nextId("vendor"),
      tenantId,
      kind: "vendor",
      version: 1,
      role,
      status: "draft",
      code,
      legalName: requireComplianceText(command.legalName, "legalName", 200),
      displayName:
        command.displayName === undefined
          ? undefined
          : requireComplianceText(command.displayName, "displayName", 200),
      regions,
      dataAssetIds,
      dataCategories: requireComplianceEnumList(
        command.dataCategories ?? [],
        COMPLIANCE_DATA_CATEGORIES,
        "dataCategories",
      ),
      parentVendorId,
      crossBorder: requireComplianceBoolean(
        command.crossBorder ?? regions.length > 0,
        "crossBorder",
      ),
      contractEffectiveAt:
        command.contractEffectiveAt === undefined
          ? undefined
          : normalizeComplianceTimestamp(
            command.contractEffectiveAt,
            "contractEffectiveAt",
          ),
      contractTerminatedAt: undefined,
      assessment: {
        status: "notStarted",
        assessedAt: undefined,
        assessedByRef: undefined,
        evidence: [],
      },
      evidence: requireComplianceEvidenceOptionalList(
        command.evidence,
        "evidence",
        COMPLIANCE_EVIDENCE_KINDS,
      ),
      createdAt: now,
      updatedAt: now,
    };
    await this.repositories.vendors.create(record);
    await this.record("vendor.create", record, command);
    return cloneComplianceValue(record);
  }

  async transitionVendor(
    command: TransitionVendorCommand,
  ): Promise<ComplianceVendor> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.vendors.get(
      tenantId,
      assertComplianceId(command.id, "vendor"),
    );
    if (current === undefined) throw complianceResourceNotFound("vendor");
    const targetStatus = requireComplianceEnum(
      command.targetStatus,
      COMPLIANCE_VENDOR_STATUSES,
      "targetStatus",
    );
    assertVendorTransition(current.status, targetStatus);
    if (targetStatus === "active") {
      if (current.assessment.status !== "passed") {
        throw complianceValidationError(
          "Compliance vendor requires a passed assessment before activation",
          "assessment.status",
        );
      }
      if (current.assessment.evidence.length === 0) {
        throw complianceValidationError(
          "Compliance vendor assessment requires evidence references",
          "assessment.evidence",
        );
      }
    }
    const saved = await this.repositories.vendors.save({
      ...current,
      version: current.version + 1,
      status: targetStatus,
      contractTerminatedAt:
        command.contractTerminatedAt === undefined
          ? current.contractTerminatedAt
          : normalizeComplianceTimestamp(
            command.contractTerminatedAt,
            "contractTerminatedAt",
          ),
      updatedAt: this.timestamp(),
    });
    await this.record("vendor.transition", saved, command, {
      fromStatus: current.status,
      toStatus: targetStatus,
    });
    return cloneComplianceValue(saved);
  }

  async recordVendorAssessment(
    command: RecordVendorAssessmentCommand,
  ): Promise<ComplianceVendor> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const current = await this.repositories.vendors.get(
      tenantId,
      assertComplianceId(command.id, "vendor"),
    );
    if (current === undefined) throw complianceResourceNotFound("vendor");
    const status = requireComplianceEnum(
      command.status,
      COMPLIANCE_ASSESSMENT_STATUSES,
      "status",
    );
    const evidence = requireComplianceEvidenceOptionalList(
      command.evidence,
      "evidence",
      COMPLIANCE_EVIDENCE_KINDS,
      { min: status === "passed" ? 1 : 0 },
    );
    const now = this.timestamp();
    const finalizing =
      status === "passed" || status === "failed" || status === "expired";
    const saved = await this.repositories.vendors.save({
      ...current,
      version: current.version + 1,
      assessment: {
        status,
        assessedAt: finalizing ? now : current.assessment.assessedAt,
        assessedByRef:
          command.assessedByRef === undefined
            ? current.assessment.assessedByRef
            : requireComplianceIdentifier(command.assessedByRef, "assessedByRef"),
        evidence: sortEvidence([...current.assessment.evidence, ...evidence]),
      },
      updatedAt: now,
    });
    await this.record("vendor.recordAssessment", saved, command, {
      toStatus: status,
    });
    return cloneComplianceValue(saved);
  }

  async getVendor(tenantId: string, id: string): Promise<ComplianceVendor | undefined> {
    return this.repositories.vendors.get(
      normalizeComplianceTenantId(tenantId),
      assertComplianceId(id, "vendor"),
    );
  }

  async listVendors(query: ComplianceListQuery): Promise<CompliancePage<ComplianceVendor>> {
    return this.listRecords(
      query,
      (tenantId) => this.repositories.vendors.list(tenantId),
      (record) => record.status,
    );
  }

  async snapshot(tenantId: string): Promise<ComplianceSnapshot> {
    const normalized = normalizeComplianceTenantId(tenantId);
    const [
      dataAssets,
      consentRecords,
      privacyRequests,
      retentionPolicies,
      retentionExecutions,
      crossBorderAssessments,
      vendors,
    ] = await Promise.all([
      this.repositories.dataAssets.list(normalized),
      this.repositories.consentRecords.list(normalized),
      this.repositories.privacyRequests.list(normalized),
      this.repositories.retentionPolicies.list(normalized),
      this.repositories.retentionExecutions.list(normalized),
      this.repositories.crossBorderAssessments.list(normalized),
      this.repositories.vendors.list(normalized),
    ]);
    return {
      dataAssets,
      consentRecords,
      privacyRequests,
      retentionPolicies,
      retentionExecutions,
      crossBorderAssessments,
      vendors,
      auditEvents: listAuditRecords(this.audit, normalized),
    };
  }

  async generateComplianceReport(
    command: GenerateComplianceReportCommand,
  ): Promise<OpenPlatformComplianceReport> {
    const tenantId = normalizeComplianceTenantId(command.tenantId);
    const generatedAt = normalizeComplianceTimestamp(
      command.generatedAt ?? this.timestamp(),
      "generatedAt",
    );
    const period = requireCompliancePeriod(command.from, command.to);
    const snapshot = await this.snapshot(tenantId);
    const report = buildComplianceReport({
      tenantId,
      generatedAt,
      period,
      dataAssets: snapshot.dataAssets,
      consentRecords: snapshot.consentRecords,
      privacyRequests: snapshot.privacyRequests,
      retentionPolicies: snapshot.retentionPolicies,
      retentionExecutions: snapshot.retentionExecutions,
      crossBorderAssessments: snapshot.crossBorderAssessments,
      vendors: snapshot.vendors,
    });
    await this.audit.append({
      tenantId,
      action: "report.generate",
      outcome: "success",
      actor: COMPLIANCE_SYSTEM_ACTOR,
      target: { type: "report", id: `report_${report.period.to}` },
      metadata: toComplianceAuditMetadata({
        periodFrom: report.period.from,
        periodTo: report.period.to,
        dataAssetCount: report.dataCatalog.assets.total,
        consentCount: report.consent.records.total,
        privacyRequestCount: report.privacyRequests.requests.total,
        gapCount: report.gaps.length,
        breached: report.privacyRequests.breached,
      }),
      occurredAt: generatedAt,
    });
    assertComplianceReportIsRedacted(report, "report");
    return report;
  }

  async listAuditEvents(tenantId: string): Promise<readonly ComplianceAuditRecord[]> {
    return listAuditRecords(this.audit, normalizeComplianceTenantId(tenantId));
  }

  async listDomainEvents(
    tenantId: string,
    options: {
      readonly kind?: ComplianceEntityKind;
      readonly recordId?: string;
      readonly fromSequence?: number;
      readonly limit?: number;
    } = {},
  ): Promise<readonly ComplianceEventRecord[]> {
    const page = await this.events.list({
      tenantId: normalizeComplianceTenantId(tenantId),
      ...options,
    });
    return page.items;
  }

  async verifyEventChain(tenantId: string): Promise<boolean> {
    return this.events.verifyChain(normalizeComplianceTenantId(tenantId));
  }

  private async record(
    action: string,
    record: ComplianceAuditableRecord,
    context: ComplianceActorContext,
    transition?: ComplianceDomainEventTransition,
    target?: ComplianceDomainEventTarget,
  ): Promise<void> {
    const occurredAt = this.timestamp();
    const event: ComplianceEventInput = {
      tenantId: record.tenantId,
      kind: record.kind,
      recordId: record.id,
      eventType: eventTypeFor(record.kind, action, transition),
      ...(transition?.fromStatus === undefined
        ? {}
        : { fromStatus: transition.fromStatus }),
      ...(transition?.toStatus === undefined
        ? {}
        : { toStatus: transition.toStatus }),
      actorRef: this.actorRef(context),
      occurredAt,
      ...(dataAssetIdsOf(record).length === 0
        ? {}
        : { dataAssetIds: dataAssetIdsOf(record) }),
    };
    await this.events.append(event);
    const auditEvent: ComplianceAuditEventInput = {
      tenantId: record.tenantId,
      action,
      outcome: "success",
      actor: context.actor ?? COMPLIANCE_SYSTEM_ACTOR,
      target: { type: record.kind, id: record.id },
      ...(context.requestId === undefined ? {} : { requestId: context.requestId }),
      metadata: toComplianceAuditMetadata(toComplianceRecordMetadata(record)),
      occurredAt,
      source: COMPLIANCE_AUDIT_SOURCE,
    };
    await this.audit.append(auditEvent);
    await this.publishDomainEvent(action, record, context, transition, target);
  }

  private async publishDomainEvent(
    action: string,
    record: ComplianceAuditableRecord,
    context: ComplianceActorContext,
    transition?: ComplianceDomainEventTransition,
    target?: ComplianceDomainEventTarget,
  ): Promise<OpenPlatformOutboxRecord | undefined> {
    const publisher = this.eventPublisher;
    if (!this.eventsEnabled || publisher === undefined) return undefined;
    let descriptor: OpenPlatformDomainEventDescriptor | undefined;
    try {
      descriptor = complianceDomainEventDescriptor({
        action,
        record,
        ...(transition === undefined ? {} : { transition }),
        ...(target === undefined ? {} : { target }),
      });
    } catch {
      return undefined;
    }
    if (descriptor === undefined) return undefined;
    const resolvedTarget = complianceDomainEventTarget(record, target);
    const scope: ComplianceDomainEventScope = {
      tenantId: record.tenantId,
      actorId: this.actorRef(context),
      operation: action,
      idempotencyKey:
        context.idempotencyKey ??
        complianceDomainEventIdempotencyKey(record, resolvedTarget?.version),
    };
    const actorRef = eventReference(scope.actorId);
    const requestId = eventReference(context.requestId);
    try {
      const recorded = await publisher.record({
        eventId: complianceDomainEventId(scope),
        tenantId: scope.tenantId,
        eventType: descriptor.eventType,
        resourceType: descriptor.resourceType,
        resourceId: descriptor.resourceId,
        ...(descriptor.resourceVersion === undefined
          ? {}
          : { resourceVersion: descriptor.resourceVersion }),
        ...(descriptor.resourceStatus === undefined
          ? {}
          : { resourceStatus: descriptor.resourceStatus }),
        ...(actorRef === undefined ? {} : { actorId: actorRef }),
        ...(requestId === undefined ? {} : { requestId }),
        occurredAt: this.timestamp(),
        ...(descriptor.data === undefined ? {} : { data: descriptor.data }),
      });
      await publisher.publish(recorded);
      return recorded;
    } catch (error) {
      if (!this.production) return undefined;
      await this.appendEventFailureAudit(scope, descriptor, error);
      throw complianceStorageUnavailable();
    }
  }

  private async appendEventFailureAudit(
    scope: ComplianceDomainEventScope,
    descriptor: OpenPlatformDomainEventDescriptor,
    error: unknown,
  ): Promise<void> {
    const targetType = complianceDomainEventAuditTargetType(
      descriptor.resourceType,
    );
    if (targetType === undefined) return;
    try {
      await this.audit.append({
        tenantId: scope.tenantId,
        action: `${scope.operation}.event`,
        outcome: "failure",
        actor: { type: "user", id: scope.actorId },
        target: { type: targetType, id: descriptor.resourceId },
        ...(scope.requestId === undefined ? {} : { requestId: scope.requestId }),
        metadata: toComplianceAuditMetadata({
          errorCode: isOpenPlatformComplianceError(error)
            ? error.code
            : COMPLIANCE_ERROR_CODES.STORAGE_UNAVAILABLE,
          eventType: descriptor.eventType,
        }),
        source: COMPLIANCE_AUDIT_SOURCE,
      });
    } catch {
      return;
    }
  }

  private async eventsOperationalReady(): Promise<boolean> {
    if (this.eventPublisher === undefined || !this.eventsEnabled) return true;
    return complianceDomainEventPublisherReady(this.eventPublisher);
  }

  private actorRef(context: ComplianceActorContext): string {
    return (context.actor ?? COMPLIANCE_SYSTEM_ACTOR).id;
  }

  private nextId(kind: ComplianceEntityKind): string {
    return complianceEntityId(kind, this.idGenerator(kind));
  }

  private timestamp(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw complianceValidationError("Compliance clock is invalid", "clock");
    }
    return value.toISOString();
  }

  private openSla(dueAt: string, at: string): ComplianceSlaEvaluation {
    const remaining = Date.parse(dueAt) - Date.parse(at);
    const state: ComplianceSlaState =
      remaining < 0
        ? "breached"
        : remaining <= COMPLIANCE_SLA_DUE_SOON_DAYS * 86_400_000
          ? "dueSoon"
          : "withinSla";
    return { state, dueAt, millisecondsRemaining: remaining };
  }

  private closeSla(
    record: CompliancePrivacyRequest,
    at: string,
    terminal: boolean,
  ): CompliancePrivacyRequest["sla"] {
    const base = record.sla;
    const respondedAt = base.respondedAt ?? at;
    if (!terminal) {
      return {
        ...base,
        respondedAt,
        state: this.openSla(base.dueAt, at).state,
      };
    }
    return {
      ...base,
      respondedAt,
      closedAt: at,
      state:
        Date.parse(at) <= Date.parse(base.dueAt) ? "closedMet" : "closedBreached",
    };
  }

  private async assertDataAssetsInTenant(
    tenantId: string,
    dataAssetIds: readonly string[],
  ): Promise<void> {
    for (const id of dataAssetIds) {
      const asset = await this.repositories.dataAssets.get(tenantId, id);
      if (asset === undefined) throw complianceResourceNotFound("dataAsset");
    }
  }

  private async listRecords<
    T extends { readonly status: string; readonly id: string; readonly createdAt: string },
  >(
    query: ComplianceListQuery,
    load: (tenantId: string) => Promise<T[]>,
    statusOf: (record: T) => string,
  ): Promise<CompliancePage<T>> {
    const tenantId = normalizeComplianceTenantId(query.tenantId);
    const limit = normalizeComplianceLimit(query.limit);
    const statusFilter =
      query.status === undefined
        ? undefined
        : requireComplianceIdentifier(query.status, "status");
    const idFilter =
      query.ids === undefined
        ? undefined
        : new Set(
          requireComplianceStringList(query.ids, "ids", { max: 100 }).map((id) =>
            requireComplianceIdentifier(id, "ids"),
          ),
        );
    const all = (await load(tenantId))
      .filter(
        (record) =>
          (statusFilter === undefined || statusOf(record) === statusFilter) &&
          (idFilter === undefined || idFilter.has(record.id)),
      )
      .sort(
        (left, right) =>
          Date.parse(left.createdAt) - Date.parse(right.createdAt) ||
          (left.id < right.id ? -1 : left.id > right.id ? 1 : 0),
      );
    const offset = decodeComplianceCursor(query.cursor, tenantId);
    const items = all.slice(offset, offset + limit);
    const nextOffset = offset + items.length;
    return {
      items: items.map((record) => cloneComplianceValue(record)),
      ...(nextOffset < all.length
        ? { nextCursor: encodeComplianceCursor(tenantId, nextOffset) }
        : {}),
      hasMore: nextOffset < all.length,
      total: all.length,
    };
  }
}

export function createComplianceService(
  options: ComplianceServiceOptions = {},
): ComplianceDomainService {
  return new ComplianceDomainService(options);
}

function listAuditRecords(
  audit: ComplianceAuditPort,
  tenantId: string,
): readonly ComplianceAuditRecord[] {
  const list = (audit as { list?: unknown }).list;
  if (typeof list === "function") {
    return (
      list as (tenantId: string) => readonly ComplianceAuditRecord[]
    ).call(audit, tenantId);
  }
  return [];
}

function eventReference(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 128) return undefined;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@-]*$/u.test(normalized)) return undefined;
  return normalized;
}

function eventTypeFor(
  kind: ComplianceEntityKind,
  action: string,
  transition: { readonly toStatus?: string } | undefined,
): string {
  const entity = (COMPLIANCE_STATEFUL_ENTITY_KINDS as readonly string[]).includes(
    kind,
  )
    ? (kind as ComplianceStatefulEntityKind)
    : undefined;
  if (entity !== undefined && transition?.toStatus !== undefined) {
    return complianceStatusTransitionEventType(entity, transition.toStatus);
  }
  return `${kind}.${action.split(".").at(-1) ?? action}`;
}

function nextIdentityStatus(
  current: CompliancePrivacyRequest["identityVerification"]["status"],
  requested: CompliancePrivacyRequest["identityVerification"]["status"],
): CompliancePrivacyRequest["identityVerification"]["status"] {
  if (requested === "verified" || requested === "failed") return requested;
  if (current === "verified") return "verified";
  if (current === "failed") return "pending";
  return requested;
}

function assertDataAssetClassification(
  classification: ComplianceDataAsset["classification"],
  personalData: boolean,
  sensitivePersonalData: boolean,
  categories: readonly ComplianceDataCategory[],
): void {
  if (sensitivePersonalData && !personalData) {
    throw complianceValidationError(
      "Compliance data asset cannot declare sensitive personal data without personal data",
      "sensitivePersonalData",
    );
  }
  if (sensitivePersonalData && classification !== "sensitivePersonal") {
    throw complianceValidationError(
      "Compliance data asset classification does not match the sensitive personal data marker",
      "classification",
    );
  }
  if (classification === "sensitivePersonal" && !sensitivePersonalData) {
    throw complianceValidationError(
      "Compliance data asset classification requires the sensitive personal data marker",
      "sensitivePersonalData",
    );
  }
  if (
    (classification === "personal" || classification === "sensitivePersonal") &&
    !personalData
  ) {
    throw complianceValidationError(
      "Compliance data asset classification requires the personal data marker",
      "personalData",
    );
  }
  if (personalData && classification !== "sensitivePersonal" && classification !== "personal") {
    throw complianceValidationError(
      "Compliance data asset declaring personal data must be classified as personal",
      "classification",
    );
  }
  if (sensitivePersonalData && !hasSensitiveCategory(categories)) {
    throw complianceValidationError(
      "Compliance data asset requires a sensitive data category",
      "categories",
    );
  }
}

function hasSensitiveCategory(
  categories: readonly ComplianceDataCategory[],
): boolean {
  return categories.some(
    (category) =>
      category === "biometric" || category === "financial" || category === "health",
  );
}

function defaultRiskLevel(
  personalData: boolean,
  sensitivePersonalData: boolean,
): ComplianceRiskLevel {
  if (sensitivePersonalData) return "high";
  if (personalData) return "medium";
  return "low";
}

function dataAssetIdsOf(record: ComplianceAuditableRecord): readonly string[] {
  switch (record.kind) {
    case "dataAsset":
      return [];
    case "consentRecord":
    case "privacyRequest":
    case "retentionPolicy":
    case "retentionExecution":
    case "crossBorderAssessment":
    case "vendor":
      return record.dataAssetIds;
  }
}

function toComplianceRecordMetadata(
  record: ComplianceAuditableRecord,
): Readonly<Record<string, unknown>> {
  switch (record.kind) {
    case "dataAsset":
      return {
        kind: record.kind,
        status: record.status,
        classification: record.classification,
        personalData: record.personalData,
        sensitivePersonalData: record.sensitivePersonalData,
        crossBorder: record.crossBorder,
        purposeCount: record.purposes.length,
        hasRetention:
          record.retentionPolicyId !== undefined || record.retentionDays !== undefined,
        evidenceCount: record.evidence.length,
      };
    case "consentRecord":
      return {
        kind: record.kind,
        status: record.status,
        policyVersion: record.policyVersion,
        channel: record.channel,
        proofCount: record.proof.length,
        withdrawn: record.status === "withdrawn",
      };
    case "privacyRequest":
      return {
        kind: record.kind,
        status: record.status,
        requestType: record.requestType,
        slaState: record.sla.state,
        identityVerification: record.identityVerification.status,
        actionCount: record.actions.length,
        decided: record.decision !== undefined,
      };
    case "retentionPolicy":
      return {
        kind: record.kind,
        status: record.status,
        trigger: record.trigger,
        action: record.action,
        retentionDays: record.retentionDays,
        legalHold: record.legalHold,
        requiresApproval: record.requiresApproval,
      };
    case "retentionExecution":
      return {
        kind: record.kind,
        status: record.status,
        action: record.action,
        recordsScanned: record.result.recordsScanned,
        recordsDeleted: record.result.recordsDeleted,
        recordsAnonymized: record.result.recordsAnonymized,
      };
    case "crossBorderAssessment":
      return {
        kind: record.kind,
        status: record.status,
        riskLevel: record.riskLevel,
        mechanismCount: record.mechanisms.length,
        personalData: record.personalData,
        sensitivePersonalData: record.sensitivePersonalData,
        destinationRegionCount: record.destinationRegions.length,
      };
    case "vendor":
      return {
        kind: record.kind,
        status: record.status,
        role: record.role,
        assessment: record.assessment.status,
        regionCount: record.regions.length,
        evidenceCount: record.evidence.length,
      };
  }
}

function sortEvidence<T extends { readonly reference: string }>(
  items: readonly T[],
): T[] {
  return [...items].sort((left, right) =>
    left.reference < right.reference ? -1 : left.reference > right.reference ? 1 : 0,
  );
}

function encodeComplianceCursor(tenantId: string, offset: number): string {
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw complianceValidationError("Compliance cursor is invalid", "cursor");
  }
  return `compliance_${Buffer.from(
    JSON.stringify({ tenantId, offset }),
    "utf8",
  ).toString("base64url")}`;
}

function decodeComplianceCursor(
  cursor: string | undefined,
  tenantId: string,
): number {
  if (cursor === undefined) return 0;
  if (typeof cursor !== "string" || !/^compliance_[A-Za-z0-9_-]+$/u.test(cursor)) {
    throw complianceValidationError("Compliance cursor is invalid", "cursor");
  }
  try {
    const parsed = JSON.parse(
      Buffer.from(cursor.slice("compliance_".length), "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    const offset = parsed.offset;
    if (
      parsed.tenantId !== tenantId ||
      typeof offset !== "number" ||
      !Number.isSafeInteger(offset) ||
      offset < 0
    ) {
      throw new Error("invalid compliance cursor scope");
    }
    return offset;
  } catch {
    throw complianceValidationError("Compliance cursor is invalid", "cursor");
  }
}
