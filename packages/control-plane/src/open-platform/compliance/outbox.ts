import { createHash } from "node:crypto";
import type {
  OpenPlatformDomainEventDescriptor,
  OpenPlatformDomainEventResourceType,
  OpenPlatformDomainEventType,
  OpenPlatformDomainEventValue,
  OpenPlatformEventPublisherPort,
} from "../events.js";
import type { OpenPlatformDependencyReadiness } from "../types.js";
import type { ComplianceAuditResourceType } from "./events.js";
import { isSensitiveComplianceField, redactComplianceText } from "./redaction.js";
import type {
  ComplianceConsentRecord,
  ComplianceCrossBorderAssessment,
  ComplianceDataAsset,
  CompliancePrivacyRequest,
  ComplianceRetentionExecution,
  ComplianceRetentionPolicy,
  ComplianceVendor,
} from "./types.js";

export const COMPLIANCE_DOMAIN_EVENT_ID_PREFIX = "open_platform_event_" as const;

export const COMPLIANCE_DOMAIN_EVENT_TEXT_MAX_LENGTH = 128;

export const COMPLIANCE_DOMAIN_EVENT_MAX_REGIONS = 32;

export const COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES = Object.freeze({
  dataAsset: "dataAsset",
  consentRecord: "consentRecord",
  privacyRequest: "privacyRequest",
  retentionPolicy: "retentionPolicy",
  crossBorderAssessment: "crossBorderAssessment",
  vendor: "vendor",
} as const satisfies Readonly<
  Record<string, OpenPlatformDomainEventResourceType>
>);

export type ComplianceDomainEventResourceKind =
  keyof typeof COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES;

export const COMPLIANCE_DOMAIN_EVENT_TYPES = Object.freeze({
  dataAssetCreated: "compliance_data_asset.created",
  dataAssetUpdated: "compliance_data_asset.updated",
  dataAssetStatusChanged: "compliance_data_asset.status_changed",
  consentRecordCreated: "compliance_consent_record.created",
  consentRecordStatusChanged: "compliance_consent_record.status_changed",
  consentRecordGranted: "compliance_consent_record.granted",
  consentRecordWithdrawn: "compliance_consent_record.withdrawn",
  privacyRequestCreated: "compliance_privacy_request.created",
  privacyRequestStatusChanged: "compliance_privacy_request.status_changed",
  privacyRequestVerified: "compliance_privacy_request.verified",
  privacyRequestDecided: "compliance_privacy_request.decided",
  retentionPolicyCreated: "compliance_retention_policy.created",
  retentionPolicyStatusChanged: "compliance_retention_policy.status_changed",
  retentionPolicyExecuted: "compliance_retention_policy.executed",
  crossBorderAssessmentCreated: "compliance_cross_border_assessment.created",
  crossBorderAssessmentStatusChanged:
    "compliance_cross_border_assessment.status_changed",
  crossBorderAssessmentDecided: "compliance_cross_border_assessment.decided",
  vendorCreated: "compliance_vendor.created",
  vendorUpdated: "compliance_vendor.updated",
  vendorStatusChanged: "compliance_vendor.status_changed",
} as const satisfies Readonly<Record<string, OpenPlatformDomainEventType>>);

export type ComplianceDomainEventKey = keyof typeof COMPLIANCE_DOMAIN_EVENT_TYPES;

export type ComplianceDomainEventType =
  (typeof COMPLIANCE_DOMAIN_EVENT_TYPES)[ComplianceDomainEventKey];

export type ComplianceDomainEventData = Readonly<
  Record<string, OpenPlatformDomainEventValue>
>;

export type ComplianceDomainEventRecord =
  | ComplianceDataAsset
  | ComplianceConsentRecord
  | CompliancePrivacyRequest
  | ComplianceRetentionPolicy
  | ComplianceRetentionExecution
  | ComplianceCrossBorderAssessment
  | ComplianceVendor;

export interface ComplianceDomainEventTransition {
  readonly fromStatus?: string;
  readonly toStatus?: string;
}

export interface ComplianceDomainEventTarget {
  readonly id: string;
  readonly version?: number;
  readonly status?: string;
}

export interface ComplianceDomainEventInput {
  readonly action: string;
  readonly record: ComplianceDomainEventRecord;
  readonly transition?: ComplianceDomainEventTransition;
  readonly target?: ComplianceDomainEventTarget;
}

export interface ComplianceDomainEventIdInput {
  readonly tenantId: string;
  readonly actorId: string;
  readonly operation: string;
  readonly idempotencyKey: string;
}

export interface ComplianceDomainEventScope extends ComplianceDomainEventIdInput {
  readonly requestId?: string;
}

export interface ComplianceDomainEventReadiness {
  readonly storage: "memory" | "database" | "persistent";
  readonly distributed: boolean;
  readonly ready: () => boolean | Promise<boolean>;
}

export function complianceDomainEventId(input: ComplianceDomainEventIdInput): string {
  const digest = createHash("sha256")
    .update(
      [
        complianceEventIdPart(input.tenantId),
        complianceEventIdPart(input.actorId),
        complianceEventIdPart(input.operation),
        complianceEventIdPart(input.idempotencyKey),
      ].join("\u0000"),
      "utf8",
    )
    .digest("hex")
    .slice(0, 32);
  return `${COMPLIANCE_DOMAIN_EVENT_ID_PREFIX}${digest}`;
}

export function complianceDomainEventIdempotencyKey(
  record: ComplianceDomainEventRecord,
  version: number | undefined = record.version,
): string {
  return `${record.id}.${version ?? 0}`;
}

export function complianceDomainEventDescriptor(
  input: ComplianceDomainEventInput,
): OpenPlatformDomainEventDescriptor | undefined {
  const binding = complianceDomainEventBinding(input.action, input.transition);
  if (binding === undefined) return undefined;
  const target = complianceDomainEventTarget(input.record, input.target);
  if (target === undefined) return undefined;
  return {
    eventType: binding.eventType,
    resourceType: binding.resourceType,
    resourceId: target.id,
    ...(target.version === undefined ? {} : { resourceVersion: target.version }),
    ...(target.status === undefined ? {} : { resourceStatus: target.status }),
    data: complianceDomainEventData(input),
  };
}

export function complianceDomainEventTarget(
  record: ComplianceDomainEventRecord,
  target?: ComplianceDomainEventTarget,
): ComplianceDomainEventTarget | undefined {
  if (target !== undefined) {
    const id = complianceEventResourceId(target.id);
    if (id === undefined) return undefined;
    const version = complianceEventResourceVersion(target.version);
    return {
      id,
      ...(version === undefined ? {} : { version }),
      ...(target.status === undefined
        ? {}
        : { status: complianceEventResourceStatus(target.status) }),
    };
  }
  const id = complianceEventResourceId(record.id);
  if (id === undefined) return undefined;
  const version = complianceEventResourceVersion(record.version);
  return {
    id,
    ...(version === undefined ? {} : { version }),
    ...(record.status === undefined
      ? {}
      : { status: complianceEventResourceStatus(record.status) }),
  };
}

export function complianceDomainEventData(
  input: ComplianceDomainEventInput,
): ComplianceDomainEventData {
  const target = complianceDomainEventTarget(input.record, input.target);
  if (target === undefined) return Object.freeze({});
  return sanitizeComplianceDomainEventData({
    operation: input.action,
    status: target.status,
    ...(input.transition?.fromStatus === undefined
      ? {}
      : { fromStatus: input.transition.fromStatus }),
    ...(input.transition?.toStatus === undefined
      ? {}
      : { toStatus: input.transition.toStatus }),
    ...complianceDomainEventMetadata(input.record, target),
  });
}

export function isComplianceDomainEventResourceKind(
  value: unknown,
): value is ComplianceDomainEventResourceKind {
  return (
    typeof value === "string" &&
    (Object.values(COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES) as readonly string[]).includes(
      value,
    )
  );
}

export function complianceDomainEventAuditTargetType(
  resourceType: OpenPlatformDomainEventResourceType,
): ComplianceAuditResourceType | undefined {
  return isComplianceDomainEventResourceKind(resourceType) ? resourceType : undefined;
}

export function sanitizeComplianceDomainEventData(
  value: Readonly<Record<string, unknown>>,
): ComplianceDomainEventData {
  const safe: Record<string, OpenPlatformDomainEventValue> = {};
  for (const key of Object.keys(value).sort()) {
    if (isSensitiveComplianceField(key)) continue;
    const item = complianceDomainEventValue(value[key]);
    if (item === undefined) continue;
    safe[key] = item;
  }
  return Object.freeze(safe);
}

export function complianceDomainEventText(
  value: string | undefined,
): string | undefined {
  if (value === undefined) return undefined;
  if (value.length > COMPLIANCE_DOMAIN_EVENT_TEXT_MAX_LENGTH) return undefined;
  if (redactComplianceText(value) !== value) return undefined;
  return value;
}

export function isComplianceEventPublisher(
  value: unknown,
): value is OpenPlatformEventPublisherPort {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof (value as OpenPlatformEventPublisherPort).record === "function" &&
    typeof (value as OpenPlatformEventPublisherPort).publish === "function"
  );
}

export function complianceDomainEventPublisherReadiness(
  publisher: OpenPlatformEventPublisherPort | undefined,
): ComplianceDomainEventReadiness | undefined {
  const readiness = publisher?.readiness;
  if (readiness === undefined) return undefined;
  return {
    storage: readiness.storage === "persistent" ? "persistent" : "memory",
    distributed: readiness.distributed === true,
    ready: () => safeComplianceReadiness(readiness),
  };
}

export async function complianceDomainEventPublisherReady(
  publisher: OpenPlatformEventPublisherPort | undefined,
): Promise<boolean> {
  const readiness = publisher?.readiness;
  if (readiness === undefined) return true;
  return safeComplianceReadiness(readiness);
}

const COMPLIANCE_DOMAIN_EVENT_REGION_PATTERN =
  /^[A-Za-z]{2}(?:-[A-Za-z0-9]{2,8}){0,2}$/u;

async function safeComplianceReadiness(
  readiness: OpenPlatformDependencyReadiness,
): Promise<boolean> {
  try {
    return (await readiness.ready()) === true;
  } catch {
    return false;
  }
}

function complianceDomainEventBinding(
  action: string,
  transition: ComplianceDomainEventTransition | undefined,
):
  | {
      readonly eventType: ComplianceDomainEventType;
      readonly resourceType: OpenPlatformDomainEventResourceType;
    }
  | undefined {
  switch (action) {
    case "dataAsset.create":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetCreated,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.dataAsset,
      };
    case "dataAsset.transition":
      return transition?.toStatus === undefined
        ? {
            eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetUpdated,
            resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.dataAsset,
          }
        : {
            eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetStatusChanged,
            resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.dataAsset,
          };
    case "consentRecord.create":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordCreated,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.consentRecord,
      };
    case "consentRecord.grant":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordGranted,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.consentRecord,
      };
    case "consentRecord.withdraw":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordWithdrawn,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.consentRecord,
      };
    case "consentRecord.transition":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordStatusChanged,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.consentRecord,
      };
    case "privacyRequest.create":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestCreated,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.privacyRequest,
      };
    case "privacyRequest.verifyIdentity":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestVerified,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.privacyRequest,
      };
    case "privacyRequest.transition":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestStatusChanged,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.privacyRequest,
      };
    case "privacyRequest.decide":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestDecided,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.privacyRequest,
      };
    case "retentionPolicy.create":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.retentionPolicyCreated,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.retentionPolicy,
      };
    case "retentionPolicy.transition":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.retentionPolicyStatusChanged,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.retentionPolicy,
      };
    case "retentionExecution.record":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.retentionPolicyExecuted,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.retentionPolicy,
      };
    case "crossBorderAssessment.create":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.crossBorderAssessmentCreated,
        resourceType:
          COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.crossBorderAssessment,
      };
    case "crossBorderAssessment.transition":
      return {
        eventType:
          COMPLIANCE_DOMAIN_EVENT_TYPES.crossBorderAssessmentStatusChanged,
        resourceType:
          COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.crossBorderAssessment,
      };
    case "crossBorderAssessment.decide":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.crossBorderAssessmentDecided,
        resourceType:
          COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.crossBorderAssessment,
      };
    case "vendor.create":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.vendorCreated,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.vendor,
      };
    case "vendor.recordAssessment":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.vendorUpdated,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.vendor,
      };
    case "vendor.transition":
      return {
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.vendorStatusChanged,
        resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.vendor,
      };
    default:
      return undefined;
  }
}

function complianceDomainEventMetadata(
  record: ComplianceDomainEventRecord,
  target: ComplianceDomainEventTarget,
): Readonly<Record<string, unknown>> {
  if (record.kind === "retentionExecution") {
    return complianceRetentionExecutionMetadata(record);
  }
  switch (record.kind) {
    case "dataAsset":
      return complianceDataAssetMetadata(record);
    case "consentRecord":
      return complianceConsentRecordMetadata(record);
    case "privacyRequest":
      return compliancePrivacyRequestMetadata(record);
    case "retentionPolicy":
      return complianceRetentionPolicyMetadata(record, target);
    case "crossBorderAssessment":
      return complianceCrossBorderAssessmentMetadata(record);
    case "vendor":
      return complianceVendorMetadata(record);
  }
}

function complianceDataAssetMetadata(
  record: ComplianceDataAsset,
): Readonly<Record<string, unknown>> {
  return {
    classification: record.classification,
    personalData: record.personalData,
    sensitivePersonalData: record.sensitivePersonalData,
    crossBorder: record.crossBorder,
    residencyRegions: record.residencyRegions,
    residencyRegionCount: record.residencyRegions.length,
    dataSubjectGroupCount: record.dataSubjects.length,
    categoryCount: record.categories.length,
    purposeCount: record.purposes.length,
    hasRetention: record.retentionPolicyId !== undefined || record.retentionDays !== undefined,
    ...(record.retentionDays === undefined
      ? {}
      : { retentionDays: record.retentionDays }),
    ...(record.retentionPolicyId === undefined
      ? {}
      : { retentionPolicyId: record.retentionPolicyId }),
    ...(record.processorVendorId === undefined
      ? {}
      : { processorVendorId: record.processorVendorId }),
  };
}

function complianceConsentRecordMetadata(
  record: ComplianceConsentRecord,
): Readonly<Record<string, unknown>> {
  return {
    channel: record.channel,
    subjectCount: record.subjectCount,
    scopeCount: record.scopes.length,
    dataAssetCount: record.dataAssetIds.length,
    granted: record.grantedAt !== undefined,
    withdrawn: record.withdrawnAt !== undefined,
    ...(record.grantedAt === undefined ? {} : { grantedAt: record.grantedAt }),
    ...(record.withdrawnAt === undefined
      ? {}
      : { withdrawnAt: record.withdrawnAt }),
    ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
  };
}

function compliancePrivacyRequestMetadata(
  record: CompliancePrivacyRequest,
): Readonly<Record<string, unknown>> {
  return {
    requestType: record.requestType,
    subjectCount: record.subjectCount,
    dataAssetCount: record.dataAssetIds.length,
    duplicate: record.duplicateOfId !== undefined,
    slaState: record.sla.state,
    slaDueAt: record.sla.dueAt,
    responseDays: record.sla.responseDays,
    identityVerificationStatus: record.identityVerification.status,
    identityVerificationAttempts: record.identityVerification.attempts,
    ...(record.identityVerification.method === undefined
      ? {}
      : { identityVerificationMethod: record.identityVerification.method }),
    ...(record.identityVerification.verifiedAt === undefined
      ? {}
      : { identityVerifiedAt: record.identityVerification.verifiedAt }),
    decided: record.decision !== undefined,
    ...(record.decision === undefined
      ? {}
      : { decision: record.decision.decision, decisionAt: record.decision.decidedAt }),
    actionCount: record.actions.length,
    affectedRecordCount: record.actions.reduce(
      (total, action) => total + (action.affectedRecords ?? 0),
      0,
    ),
    ...(record.sla.respondedAt === undefined
      ? {}
      : { slaRespondedAt: record.sla.respondedAt }),
    ...(record.sla.closedAt === undefined ? {} : { slaClosedAt: record.sla.closedAt }),
  };
}

function complianceRetentionPolicyMetadata(
  record: ComplianceRetentionPolicy,
  target: ComplianceDomainEventTarget,
): Readonly<Record<string, unknown>> {
  return {
    trigger: record.trigger,
    retentionAction: record.action,
    retentionDays: record.retentionDays,
    requiresApproval: record.requiresApproval,
    legalHold: record.legalHold,
    dataAssetCount: record.dataAssetIds.length,
    residencyRegionCount: record.residencyRegions.length,
    policyVersion: target.version,
    hasExecution: record.lastExecutionId !== undefined,
  };
}

function complianceRetentionExecutionMetadata(
  record: ComplianceRetentionExecution,
): Readonly<Record<string, unknown>> {
  return {
    runId: record.runId,
    retentionAction: record.action,
    dataAssetCount: record.dataAssetIds.length,
    recordsScanned: record.result.recordsScanned,
    recordsDeleted: record.result.recordsDeleted,
    recordsAnonymized: record.result.recordsAnonymized,
    recordsArchived: record.result.recordsArchived,
    blocked: record.blockedReason !== undefined,
    ...(record.result.completedAt === undefined
      ? {}
      : { completedAt: record.result.completedAt }),
  };
}

function complianceCrossBorderAssessmentMetadata(
  record: ComplianceCrossBorderAssessment,
): Readonly<Record<string, unknown>> {
  return {
    riskLevel: record.riskLevel,
    personalData: record.personalData,
    sensitivePersonalData: record.sensitivePersonalData,
    sourceRegion: record.sourceRegion,
    destinationRegions: record.destinationRegions,
    destinationRegionCount: record.destinationRegions.length,
    mechanismCount: record.mechanisms.length,
    dataAssetCount: record.dataAssetIds.length,
    riskFactorCount: record.riskFactors.length,
    decided: record.decidedAt !== undefined,
    ...(record.decidedAt === undefined ? {} : { decisionAt: record.decidedAt }),
    ...(record.validUntil === undefined ? {} : { validUntil: record.validUntil }),
  };
}

function complianceVendorMetadata(
  record: ComplianceVendor,
): Readonly<Record<string, unknown>> {
  return {
    role: record.role,
    crossBorder: record.crossBorder,
    regions: record.regions,
    regionCount: record.regions.length,
    dataAssetCount: record.dataAssetIds.length,
    dataCategoryCount: record.dataCategories.length,
    parentVendor: record.parentVendorId !== undefined,
    assessmentStatus: record.assessment.status,
    ...(record.assessment.assessedAt === undefined
      ? {}
      : { assessmentAt: record.assessment.assessedAt }),
    ...(record.contractEffectiveAt === undefined
      ? {}
      : { contractEffectiveAt: record.contractEffectiveAt }),
    ...(record.contractTerminatedAt === undefined
      ? {}
      : { contractTerminatedAt: record.contractTerminatedAt }),
  };
}

function complianceDomainEventValue(
  value: unknown,
): OpenPlatformDomainEventValue | undefined {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === "string") return complianceDomainEventText(value);
  if (Array.isArray(value)) return complianceDomainEventRegionList(value);
  return undefined;
}

function complianceDomainEventRegionList(
  value: readonly unknown[],
): readonly string[] | undefined {
  if (value.length === 0 || value.length > COMPLIANCE_DOMAIN_EVENT_MAX_REGIONS) {
    return undefined;
  }
  const regions: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") return undefined;
    if (!COMPLIANCE_DOMAIN_EVENT_REGION_PATTERN.test(item)) return undefined;
    if (regions.includes(item)) return undefined;
    regions.push(item);
  }
  return Object.freeze(regions);
}

function complianceEventIdPart(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function complianceEventResourceId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 128) return undefined;
  return /^[A-Za-z0-9][A-Za-z0-9._:@-]*$/u.test(normalized) ? normalized : undefined;
}

function complianceEventResourceVersion(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    return undefined;
  }
  return value;
}

function complianceEventResourceStatus(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 128) return undefined;
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(normalized) ? normalized : undefined;
}
