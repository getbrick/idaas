import { maskOpenPlatformComplianceSubjectRef } from "@getbrick/idaas-contracts";
import { complianceValidationError } from "./errors.js";
import { assertComplianceReportIsRedacted, redactComplianceText } from "./redaction.js";
import type {
  ComplianceConsentRecord,
  ComplianceCrossBorderAssessment,
  ComplianceDataAsset,
  ComplianceEvidence,
  CompliancePrivacyRequest,
  ComplianceReport,
  ComplianceRetentionExecution,
  ComplianceRetentionPolicy,
  ComplianceVendor,
} from "./types.js";
import type { CompliancePage, ComplianceSlaEvaluation } from "./service.js";

export interface ComplianceEvidenceView {
  readonly reference: string;
  readonly kind: ComplianceEvidence["kind"];
  readonly recordedAt?: string;
}

export interface ComplianceDataAssetView {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "dataAsset";
  readonly version: number;
  readonly name: string;
  readonly code: string;
  readonly status: ComplianceDataAsset["status"];
  readonly classification: ComplianceDataAsset["classification"];
  readonly categories: readonly ComplianceDataAsset["categories"][number][];
  readonly personalData: boolean;
  readonly sensitivePersonalData: boolean;
  readonly legalBasis?: ComplianceDataAsset["legalBasis"];
  readonly purposes: readonly string[];
  readonly dataSubjects: readonly ComplianceDataAsset["dataSubjects"][number][];
  readonly residencyRegions: readonly string[];
  readonly processorVendorId?: string;
  readonly retentionPolicyId?: string;
  readonly retentionDays?: number;
  readonly crossBorder: boolean;
  readonly evidence: readonly ComplianceEvidenceView[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ComplianceConsentRecordView {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "consentRecord";
  readonly version: number;
  readonly status: ComplianceConsentRecord["status"];
  readonly subjectRefMasked: string;
  readonly subjectCount: number;
  readonly purpose: string;
  readonly legalBasis: "consent";
  readonly policyVersion: string;
  readonly channel: ComplianceConsentRecord["channel"];
  readonly language?: string;
  readonly scopes: readonly string[];
  readonly dataAssetIds: readonly string[];
  readonly grantedAt?: string;
  readonly withdrawnAt?: string;
  readonly expiresAt?: string;
  readonly withdrawalReason?: string;
  readonly proof: readonly ComplianceEvidenceView[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ComplianceIdentityVerificationView {
  readonly status: CompliancePrivacyRequest["identityVerification"]["status"];
  readonly method?: CompliancePrivacyRequest["identityVerification"]["method"];
  readonly attempts: number;
  readonly verifiedAt?: string;
  readonly verifiedByRef?: string;
  readonly evidence: readonly ComplianceEvidenceView[];
}

export interface CompliancePrivacyRequestDecisionView {
  readonly decision: NonNullable<CompliancePrivacyRequest["decision"]>["decision"];
  readonly decidedAt: string;
  readonly decidedByRef: string;
  readonly rationale?: string;
  readonly evidence: readonly ComplianceEvidenceView[];
}

export interface CompliancePrivacyRequestActionView {
  readonly action: CompliancePrivacyRequest["actions"][number]["action"];
  readonly dataAssetId: string;
  readonly executedAt: string;
  readonly affectedRecords?: number;
  readonly executionRef?: string;
}

export interface CompliancePrivacyRequestView {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "privacyRequest";
  readonly version: number;
  readonly requestType: CompliancePrivacyRequest["requestType"];
  readonly status: CompliancePrivacyRequest["status"];
  readonly statusReason?: string;
  readonly subjectRefMasked: string;
  readonly subjectCount: number;
  readonly dataAssetIds: readonly string[];
  readonly identityVerification: ComplianceIdentityVerificationView;
  readonly sla: CompliancePrivacyRequest["sla"];
  readonly decision?: CompliancePrivacyRequestDecisionView;
  readonly actions: readonly CompliancePrivacyRequestActionView[];
  readonly duplicateOfId?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CompliancePrivacyRequestSlaView {
  readonly id: string;
  readonly requestId: string;
  readonly requestType: CompliancePrivacyRequest["requestType"];
  readonly status: CompliancePrivacyRequest["status"];
  readonly policyCode: string;
  readonly responseDays: number;
  readonly dueAt: string;
  readonly respondedAt?: string;
  readonly closedAt?: string;
  readonly state: CompliancePrivacyRequest["sla"]["state"];
  readonly millisecondsRemaining: number;
}

export interface ComplianceRetentionPolicyView {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "retentionPolicy";
  readonly version: number;
  readonly name: string;
  readonly code: string;
  readonly status: ComplianceRetentionPolicy["status"];
  readonly trigger: ComplianceRetentionPolicy["trigger"];
  readonly action: ComplianceRetentionPolicy["action"];
  readonly retentionDays: number;
  readonly requiresApproval: boolean;
  readonly legalHold: boolean;
  readonly dataAssetIds: readonly string[];
  readonly residencyRegions: readonly string[];
  readonly lastExecutionId?: string;
  readonly evidence: readonly ComplianceEvidenceView[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ComplianceRetentionExecutionView {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "retentionExecution";
  readonly version: number;
  readonly policyId: string;
  readonly runId: string;
  readonly dataAssetIds: readonly string[];
  readonly status: ComplianceRetentionExecution["status"];
  readonly action: ComplianceRetentionExecution["action"];
  readonly blockedReason?: string;
  readonly recordsScanned: number;
  readonly recordsDeleted: number;
  readonly recordsAnonymized: number;
  readonly recordsArchived: number;
  readonly completedAt?: string;
  readonly failureReason?: string;
  readonly recordedByRef: string;
  readonly occurredAt: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly evidence: readonly ComplianceEvidenceView[];
}

export interface ComplianceCrossBorderAssessmentView {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "crossBorderAssessment";
  readonly version: number;
  readonly title: string;
  readonly code: string;
  readonly status: ComplianceCrossBorderAssessment["status"];
  readonly sourceRegion: string;
  readonly destinationRegions: readonly string[];
  readonly transferPurpose: string;
  readonly dataAssetIds: readonly string[];
  readonly personalData: boolean;
  readonly sensitivePersonalData: boolean;
  readonly riskLevel: ComplianceCrossBorderAssessment["riskLevel"];
  readonly riskFactors: readonly string[];
  readonly mechanisms: readonly ComplianceCrossBorderAssessment["mechanisms"][number][];
  readonly recipientVendorId?: string;
  readonly decidedAt?: string;
  readonly decidedByRef?: string;
  readonly validUntil?: string;
  readonly evidence: readonly ComplianceEvidenceView[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ComplianceVendorAssessmentView {
  readonly status: ComplianceVendor["assessment"]["status"];
  readonly assessedAt?: string;
  readonly assessedByRef?: string;
  readonly evidence: readonly ComplianceEvidenceView[];
}

export interface ComplianceVendorView {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "vendor";
  readonly version: number;
  readonly role: ComplianceVendor["role"];
  readonly status: ComplianceVendor["status"];
  readonly code: string;
  readonly legalName: string;
  readonly displayName?: string;
  readonly regions: readonly string[];
  readonly dataAssetIds: readonly string[];
  readonly dataCategories: readonly ComplianceVendor["dataCategories"][number][];
  readonly parentVendorId?: string;
  readonly crossBorder: boolean;
  readonly contractEffectiveAt?: string;
  readonly contractTerminatedAt?: string;
  readonly assessment: ComplianceVendorAssessmentView;
  readonly evidence: readonly ComplianceEvidenceView[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type ComplianceRecordView =
  | ComplianceDataAssetView
  | ComplianceConsentRecordView
  | CompliancePrivacyRequestView
  | ComplianceRetentionPolicyView
  | ComplianceRetentionExecutionView
  | ComplianceCrossBorderAssessmentView
  | ComplianceVendorView;

export interface CompliancePageView<T> {
  readonly items: readonly T[];
  readonly nextCursor?: string;
  readonly hasMore: boolean;
  readonly total: number;
}

export function toComplianceDataAssetView(
  record: ComplianceDataAsset,
): ComplianceDataAssetView {
  return freeze(assertComplianceViewIsRedacted({
    id: record.id,
    tenantId: record.tenantId,
    kind: "dataAsset" as const,
    version: record.version,
    name: redactComplianceText(record.name),
    code: record.code,
    status: record.status,
    classification: record.classification,
    categories: [...record.categories],
    personalData: record.personalData,
    sensitivePersonalData: record.sensitivePersonalData,
    ...(record.legalBasis === undefined ? {} : { legalBasis: record.legalBasis }),
    purposes: record.purposes.map((purpose) => redactComplianceText(purpose)),
    dataSubjects: [...record.dataSubjects],
    residencyRegions: [...record.residencyRegions],
    ...(record.processorVendorId === undefined
      ? {}
      : { processorVendorId: record.processorVendorId }),
    ...(record.retentionPolicyId === undefined
      ? {}
      : { retentionPolicyId: record.retentionPolicyId }),
    ...(record.retentionDays === undefined
      ? {}
      : { retentionDays: record.retentionDays }),
    crossBorder: record.crossBorder,
    evidence: toComplianceEvidenceViews(record.evidence),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  }, "dataAsset")) as ComplianceDataAssetView;
}

export function toComplianceConsentRecordView(
  record: ComplianceConsentRecord,
): ComplianceConsentRecordView {
  return freeze(assertComplianceViewIsRedacted({
    id: record.id,
    tenantId: record.tenantId,
    kind: "consentRecord" as const,
    version: record.version,
    status: record.status,
    subjectRefMasked: maskComplianceSubjectRef(record.subjectRef),
    subjectCount: record.subjectCount,
    purpose: redactComplianceText(record.purpose),
    legalBasis: "consent" as const,
    policyVersion: record.policyVersion,
    channel: record.channel,
    ...(record.language === undefined ? {} : { language: record.language }),
    scopes: record.scopes.map((scope) => redactComplianceText(scope)),
    dataAssetIds: [...record.dataAssetIds],
    ...(record.grantedAt === undefined ? {} : { grantedAt: record.grantedAt }),
    ...(record.withdrawnAt === undefined ? {} : { withdrawnAt: record.withdrawnAt }),
    ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
    ...(record.withdrawalReason === undefined
      ? {}
      : { withdrawalReason: redactComplianceText(record.withdrawalReason) }),
    proof: toComplianceEvidenceViews(record.proof),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  }, "consentRecord")) as ComplianceConsentRecordView;
}

export function toCompliancePrivacyRequestView(
  record: CompliancePrivacyRequest,
): CompliancePrivacyRequestView {
  return freeze(assertComplianceViewIsRedacted({
    id: record.id,
    tenantId: record.tenantId,
    kind: "privacyRequest" as const,
    version: record.version,
    requestType: record.requestType,
    status: record.status,
    ...(record.statusReason === undefined
      ? {}
      : { statusReason: redactComplianceText(record.statusReason) }),
    subjectRefMasked: maskComplianceSubjectRef(record.subjectRef),
    subjectCount: record.subjectCount,
    dataAssetIds: [...record.dataAssetIds],
    identityVerification: {
      status: record.identityVerification.status,
      ...(record.identityVerification.method === undefined
        ? {}
        : { method: record.identityVerification.method }),
      attempts: record.identityVerification.attempts,
      ...(record.identityVerification.verifiedAt === undefined
        ? {}
        : { verifiedAt: record.identityVerification.verifiedAt }),
      ...(record.identityVerification.verifiedByRef === undefined
        ? {}
        : {
          verifiedByRef: redactComplianceText(record.identityVerification.verifiedByRef),
        }),
      evidence: toComplianceEvidenceViews(record.identityVerification.evidence),
    },
    sla: {
      policyCode: record.sla.policyCode,
      responseDays: record.sla.responseDays,
      dueAt: record.sla.dueAt,
      ...(record.sla.respondedAt === undefined
        ? {}
        : { respondedAt: record.sla.respondedAt }),
      ...(record.sla.closedAt === undefined ? {} : { closedAt: record.sla.closedAt }),
      state: record.sla.state,
    },
    ...(record.decision === undefined
      ? {}
      : {
        decision: {
          decision: record.decision.decision,
          decidedAt: record.decision.decidedAt,
          decidedByRef: redactComplianceText(record.decision.decidedByRef),
          ...(record.decision.rationale === undefined
            ? {}
            : { rationale: redactComplianceText(record.decision.rationale) }),
          evidence: toComplianceEvidenceViews(record.decision.evidence),
        },
      }),
    actions: record.actions.map((action) => ({
      action: action.action,
      dataAssetId: action.dataAssetId,
      executedAt: action.executedAt,
      ...(action.affectedRecords === undefined
        ? {}
        : { affectedRecords: action.affectedRecords }),
      ...(action.executionRef === undefined
        ? {}
        : { executionRef: redactComplianceText(action.executionRef) }),
    })),
    ...(record.duplicateOfId === undefined ? {} : { duplicateOfId: record.duplicateOfId }),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  }, "privacyRequest")) as CompliancePrivacyRequestView;
}

export function toCompliancePrivacyRequestSlaView(
  record: CompliancePrivacyRequest,
  evaluation: ComplianceSlaEvaluation,
): CompliancePrivacyRequestSlaView {
  return freeze(assertComplianceViewIsRedacted({
    id: `${record.id}_sla`,
    requestId: record.id,
    requestType: record.requestType,
    status: record.status,
    policyCode: record.sla.policyCode,
    responseDays: record.sla.responseDays,
    dueAt: evaluation.dueAt,
    ...(record.sla.respondedAt === undefined ? {} : { respondedAt: record.sla.respondedAt }),
    ...(record.sla.closedAt === undefined ? {} : { closedAt: record.sla.closedAt }),
    state: evaluation.state,
    millisecondsRemaining: evaluation.millisecondsRemaining,
  }, "privacyRequestSla")) as CompliancePrivacyRequestSlaView;
}

export function toComplianceRetentionPolicyView(
  record: ComplianceRetentionPolicy,
): ComplianceRetentionPolicyView {
  return freeze(assertComplianceViewIsRedacted({
    id: record.id,
    tenantId: record.tenantId,
    kind: "retentionPolicy" as const,
    version: record.version,
    name: redactComplianceText(record.name),
    code: record.code,
    status: record.status,
    trigger: record.trigger,
    action: record.action,
    retentionDays: record.retentionDays,
    requiresApproval: record.requiresApproval,
    legalHold: record.legalHold,
    dataAssetIds: [...record.dataAssetIds],
    residencyRegions: [...record.residencyRegions],
    ...(record.lastExecutionId === undefined
      ? {}
      : { lastExecutionId: record.lastExecutionId }),
    evidence: toComplianceEvidenceViews(record.evidence),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  }, "retentionPolicy")) as ComplianceRetentionPolicyView;
}

export function toComplianceRetentionExecutionView(
  record: ComplianceRetentionExecution,
): ComplianceRetentionExecutionView {
  return freeze(assertComplianceViewIsRedacted({
    id: record.id,
    tenantId: record.tenantId,
    kind: "retentionExecution" as const,
    version: record.version,
    policyId: record.policyId,
    runId: record.runId,
    dataAssetIds: [...record.dataAssetIds],
    status: record.status,
    action: record.action,
    ...(record.blockedReason === undefined
      ? {}
      : { blockedReason: redactComplianceText(record.blockedReason) }),
    recordsScanned: record.result.recordsScanned,
    recordsDeleted: record.result.recordsDeleted,
    recordsAnonymized: record.result.recordsAnonymized,
    recordsArchived: record.result.recordsArchived,
    ...(record.result.completedAt === undefined
      ? {}
      : { completedAt: record.result.completedAt }),
    ...(record.result.failureReason === undefined
      ? {}
      : { failureReason: redactComplianceText(record.result.failureReason) }),
    recordedByRef: redactComplianceText(record.recordedByRef),
    occurredAt: record.occurredAt,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    evidence: toComplianceEvidenceViews(record.result.evidence),
  }, "retentionExecution")) as ComplianceRetentionExecutionView;
}

export function toComplianceCrossBorderAssessmentView(
  record: ComplianceCrossBorderAssessment,
): ComplianceCrossBorderAssessmentView {
  return freeze(assertComplianceViewIsRedacted({
    id: record.id,
    tenantId: record.tenantId,
    kind: "crossBorderAssessment" as const,
    version: record.version,
    title: redactComplianceText(record.title),
    code: record.code,
    status: record.status,
    sourceRegion: record.sourceRegion,
    destinationRegions: [...record.destinationRegions],
    transferPurpose: redactComplianceText(record.transferPurpose),
    dataAssetIds: [...record.dataAssetIds],
    personalData: record.personalData,
    sensitivePersonalData: record.sensitivePersonalData,
    riskLevel: record.riskLevel,
    riskFactors: record.riskFactors.map((factor) => redactComplianceText(factor)),
    mechanisms: [...record.mechanisms],
    ...(record.recipientVendorId === undefined
      ? {}
      : { recipientVendorId: record.recipientVendorId }),
    ...(record.decidedAt === undefined ? {} : { decidedAt: record.decidedAt }),
    ...(record.decidedByRef === undefined
      ? {}
      : { decidedByRef: redactComplianceText(record.decidedByRef) }),
    ...(record.validUntil === undefined ? {} : { validUntil: record.validUntil }),
    evidence: toComplianceEvidenceViews(record.evidence),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  }, "crossBorderAssessment")) as ComplianceCrossBorderAssessmentView;
}

export function toComplianceVendorView(
  record: ComplianceVendor,
): ComplianceVendorView {
  return freeze(assertComplianceViewIsRedacted({
    id: record.id,
    tenantId: record.tenantId,
    kind: "vendor" as const,
    version: record.version,
    role: record.role,
    status: record.status,
    code: record.code,
    legalName: redactComplianceText(record.legalName),
    ...(record.displayName === undefined
      ? {}
      : { displayName: redactComplianceText(record.displayName) }),
    regions: [...record.regions],
    dataAssetIds: [...record.dataAssetIds],
    dataCategories: [...record.dataCategories],
    ...(record.parentVendorId === undefined
      ? {}
      : { parentVendorId: record.parentVendorId }),
    crossBorder: record.crossBorder,
    ...(record.contractEffectiveAt === undefined
      ? {}
      : { contractEffectiveAt: record.contractEffectiveAt }),
    ...(record.contractTerminatedAt === undefined
      ? {}
      : { contractTerminatedAt: record.contractTerminatedAt }),
    assessment: {
      status: record.assessment.status,
      ...(record.assessment.assessedAt === undefined
        ? {}
        : { assessedAt: record.assessment.assessedAt }),
      ...(record.assessment.assessedByRef === undefined
        ? {}
        : { assessedByRef: redactComplianceText(record.assessment.assessedByRef) }),
      evidence: toComplianceEvidenceViews(record.assessment.evidence),
    },
    evidence: toComplianceEvidenceViews(record.evidence),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  }, "vendor")) as ComplianceVendorView;
}

export function toComplianceReportView(
  report: ComplianceReport,
): ComplianceReport {
  return freeze(assertComplianceViewIsRedacted(
    structuredClone(report),
    "report",
  )) as ComplianceReport;
}

export function toComplianceDataAssetViews(
  records: readonly ComplianceDataAsset[],
): readonly ComplianceDataAssetView[] {
  return records.map(toComplianceDataAssetView);
}

export function toComplianceConsentRecordViews(
  records: readonly ComplianceConsentRecord[],
): readonly ComplianceConsentRecordView[] {
  return records.map(toComplianceConsentRecordView);
}

export function toCompliancePrivacyRequestViews(
  records: readonly CompliancePrivacyRequest[],
): readonly CompliancePrivacyRequestView[] {
  return records.map(toCompliancePrivacyRequestView);
}

export function toComplianceRetentionPolicyViews(
  records: readonly ComplianceRetentionPolicy[],
): readonly ComplianceRetentionPolicyView[] {
  return records.map(toComplianceRetentionPolicyView);
}

export function toComplianceRetentionExecutionViews(
  records: readonly ComplianceRetentionExecution[],
): readonly ComplianceRetentionExecutionView[] {
  return records.map(toComplianceRetentionExecutionView);
}

export function toComplianceCrossBorderAssessmentViews(
  records: readonly ComplianceCrossBorderAssessment[],
): readonly ComplianceCrossBorderAssessmentView[] {
  return records.map(toComplianceCrossBorderAssessmentView);
}

export function toComplianceVendorViews(
  records: readonly ComplianceVendor[],
): readonly ComplianceVendorView[] {
  return records.map(toComplianceVendorView);
}

export function maskComplianceSubjectRef(value: string): string {
  return redactComplianceText(maskOpenPlatformComplianceSubjectRef(value));
}

export function toComplianceEvidenceViews(
  evidence: readonly ComplianceEvidence[],
): readonly ComplianceEvidenceView[] {
  return evidence.map((item) => ({
    reference: redactComplianceText(item.reference),
    kind: item.kind,
    ...(item.recordedAt === undefined ? {} : { recordedAt: item.recordedAt }),
  }));
}

export function assertComplianceViewIsRedacted<T>(value: T, field: string): T {
  assertComplianceReportIsRedacted(value, field);
  return value;
}

export function toCompliancePageView<TItem, TView>(
  page: CompliancePage<TItem>,
  toView: (item: TItem) => TView,
): CompliancePageView<TView> {
  if (page === null || typeof page !== "object") {
    throw complianceValidationError("Compliance page is invalid", "page");
  }
  return {
    items: page.items.map(toView),
    ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
    hasMore: page.hasMore,
    total: page.total,
  };
}

function freeze<T>(value: T): T {
  deepFreezeValue(value);
  return Object.freeze(value);
}

function deepFreezeValue(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  for (const item of Object.values(value as Record<string, unknown>)) {
    deepFreezeValue(item);
  }
  Object.freeze(value);
}
