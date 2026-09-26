import type {
  OpenPlatformComplianceCountBreakdown,
  OpenPlatformComplianceReport,
  OpenPlatformComplianceReportGap,
} from "@getbrick/idaas-contracts";
import { OPEN_PLATFORM_COMPLIANCE_REDACTED } from "@getbrick/idaas-contracts";
import { assertComplianceReportIsRedacted } from "./redaction.js";
import {
  COMPLIANCE_REDACTED,
  COMPLIANCE_REPORT_GAP_CODES,
  COMPLIANCE_REPORT_LIMITATIONS,
  type ComplianceConsentRecord,
  type ComplianceCrossBorderAssessment,
  type ComplianceDataAsset,
  type CompliancePrivacyRequest,
  type ComplianceReportGapCode,
  type ComplianceRetentionExecution,
  type ComplianceRetentionPolicy,
  type ComplianceVendor,
} from "./types.js";
import { isTerminalPrivacyRequestStatus } from "./repositories.js";
import { requireCompliancePeriod } from "./validation.js";

export interface ComplianceReportInput {
  readonly tenantId: string;
  readonly generatedAt: string;
  readonly period: { readonly from: string; readonly to: string };
  readonly dataAssets: readonly ComplianceDataAsset[];
  readonly consentRecords: readonly ComplianceConsentRecord[];
  readonly privacyRequests: readonly CompliancePrivacyRequest[];
  readonly retentionPolicies: readonly ComplianceRetentionPolicy[];
  readonly retentionExecutions: readonly ComplianceRetentionExecution[];
  readonly crossBorderAssessments: readonly ComplianceCrossBorderAssessment[];
  readonly vendors: readonly ComplianceVendor[];
}

export function buildComplianceReport(
  input: ComplianceReportInput,
): OpenPlatformComplianceReport {
  const period = requireCompliancePeriod(input.period.from, input.period.to);
  const generatedAt = new Date(input.generatedAt).toISOString();
  const activeAssetIds = new Set(
    input.dataAssets
      .filter((asset) => asset.status === "active" || asset.status === "registered")
      .map((asset) => asset.id),
  );
  const gaps: OpenPlatformComplianceReportGap[] = [
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.DATA_ASSET_WITHOUT_PURPOSE,
      input.dataAssets.filter((asset) => asset.purposes.length === 0).map((asset) => asset.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.DATA_ASSET_WITHOUT_RETENTION_POLICY,
      input.dataAssets
        .filter(
          (asset) =>
            asset.retentionPolicyId === undefined &&
            asset.retentionDays === undefined,
        )
        .map((asset) => asset.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.SENSITIVE_DATA_ASSET_WITHOUT_LEGAL_BASIS,
      input.dataAssets
        .filter((asset) => asset.sensitivePersonalData && asset.legalBasis === undefined)
        .map((asset) => asset.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.CONSENT_WITHDRAWN_WHILE_ASSET_ACTIVE,
      input.consentRecords
        .filter(
          (record) =>
            record.status === "withdrawn" &&
            record.dataAssetIds.some((id) => activeAssetIds.has(id)),
        )
        .map((record) => record.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.PRIVACY_REQUEST_WITHOUT_IDENTITY_VERIFICATION,
      input.privacyRequests
        .filter(
          (record) =>
            !isTerminalPrivacyRequestStatus(record.status) &&
            record.identityVerification.status !== "verified",
        )
        .map((record) => record.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.PRIVACY_REQUEST_SLA_BREACHED,
      input.privacyRequests
        .filter(
          (record) =>
            record.sla.state === "breached" || record.sla.state === "closedBreached",
        )
        .map((record) => record.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.RETENTION_EXECUTION_FAILED,
      input.retentionExecutions
        .filter((record) => record.status === "failed" || record.status === "blocked")
        .map((record) => record.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.CROSS_BORDER_WITHOUT_MECHANISM,
      input.crossBorderAssessments
        .filter(
          (record) =>
            (record.personalData || record.sensitivePersonalData) &&
            record.mechanisms.length === 0 &&
            record.status !== "rejected" &&
            record.status !== "withdrawn",
        )
        .map((record) => record.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.CROSS_BORDER_AWAITING_DECISION,
      input.crossBorderAssessments
        .filter(
          (record) =>
            record.status === "draft" ||
            record.status === "assessing" ||
            record.status === "pendingApproval",
        )
        .map((record) => record.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.VENDOR_ASSESSMENT_INCOMPLETE,
      input.vendors
        .filter(
          (record) =>
            record.status !== "terminated" &&
            record.assessment.status !== "passed",
        )
        .map((record) => record.id),
    ),
    gapOf(
      COMPLIANCE_REPORT_GAP_CODES.SUB_PROCESSOR_WITHOUT_PARENT,
      input.vendors
        .filter(
          (record) => record.role === "subProcessor" && record.parentVendorId === undefined,
        )
        .map((record) => record.id),
    ),
  ].filter((gap) => gap !== undefined);

  const openRequests = input.privacyRequests.filter(
    (record) => !isTerminalPrivacyRequestStatus(record.status),
  );
  const report: OpenPlatformComplianceReport = {
    contractVersion: 1,
    tenantId: input.tenantId,
    generatedAt,
    period,
    redaction: { placeholder: OPEN_PLATFORM_COMPLIANCE_REDACTED, applies: true },
    dataCatalog: {
      assets: breakdown(input.dataAssets, (asset) => asset.status),
      byClassification: breakdown(input.dataAssets, (asset) => asset.classification),
      personalDataAssets: input.dataAssets.filter((asset) => asset.personalData).length,
      sensitivePersonalDataAssets: input.dataAssets.filter(
        (asset) => asset.sensitivePersonalData,
      ).length,
      crossBorderAssets: input.dataAssets.filter((asset) => asset.crossBorder).length,
      withoutPurpose: gaps.find(
        (gap) => gap.code === COMPLIANCE_REPORT_GAP_CODES.DATA_ASSET_WITHOUT_PURPOSE,
      )?.resourceIds ?? [],
      withoutRetentionPolicy: gaps.find(
        (gap) =>
          gap.code === COMPLIANCE_REPORT_GAP_CODES.DATA_ASSET_WITHOUT_RETENTION_POLICY,
      )?.resourceIds ?? [],
    },
    consent: {
      records: breakdown(input.consentRecords, (record) => record.status),
      activeSubjects: distinctSubjects(
        input.consentRecords.filter((record) => record.status === "granted"),
      ),
      withdrawnSubjects: distinctSubjects(
        input.consentRecords.filter((record) => record.status === "withdrawn"),
      ),
      withdrawnProofCount: input.consentRecords
        .filter((record) => record.status === "withdrawn")
        .reduce((total, record) => total + record.proof.length, 0),
    },
    privacyRequests: {
      requests: breakdown(input.privacyRequests, (record) => record.status),
      awaitingIdentityVerification: input.privacyRequests.filter(
        (record) =>
          !isTerminalPrivacyRequestStatus(record.status) &&
          record.identityVerification.status !== "verified",
      ).length,
      fulfilledWithinSla: input.privacyRequests.filter(
        (record) =>
          (record.status === "fulfilled" || record.status === "partiallyFulfilled") &&
          record.sla.state === "closedMet",
      ).length,
      breached: input.privacyRequests.filter(
        (record) =>
          record.sla.state === "breached" || record.sla.state === "closedBreached",
      ).length,
      oldestOpenDays: oldestOpenDays(openRequests, generatedAt),
    },
    retention: {
      policies: breakdown(input.retentionPolicies, (record) => record.status),
      executions: breakdown(input.retentionExecutions, (record) => record.status),
      recordsDeleted: input.retentionExecutions.reduce(
        (total, record) => total + record.result.recordsDeleted,
        0,
      ),
      recordsAnonymized: input.retentionExecutions.reduce(
        (total, record) => total + record.result.recordsAnonymized,
        0,
      ),
      failedExecutions: gaps.find(
        (gap) => gap.code === COMPLIANCE_REPORT_GAP_CODES.RETENTION_EXECUTION_FAILED,
      )?.resourceIds ?? [],
    },
    crossBorder: {
      assessments: breakdown(input.crossBorderAssessments, (record) => record.status),
      byRiskLevel: breakdown(input.crossBorderAssessments, (record) => record.riskLevel),
      withoutMechanism: gaps.find(
        (gap) =>
          gap.code === COMPLIANCE_REPORT_GAP_CODES.CROSS_BORDER_WITHOUT_MECHANISM,
      )?.resourceIds ?? [],
      awaitingDecision: gaps.find(
        (gap) =>
          gap.code === COMPLIANCE_REPORT_GAP_CODES.CROSS_BORDER_AWAITING_DECISION,
      )?.resourceIds ?? [],
    },
    vendors: {
      vendors: breakdown(input.vendors, (record) => record.status),
      byRole: breakdown(input.vendors, (record) => record.role),
      assessment: breakdown(input.vendors, (record) => record.assessment.status),
      regions: [
        ...new Set(input.vendors.flatMap((record) => record.regions)),
      ].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)),
    },
    gaps,
    limitations: [...COMPLIANCE_REPORT_LIMITATIONS],
  };
  assertComplianceReportIsRedacted(report, "report");
  return deepFreezeReport(report);
}

export function complianceReportRedactionPlaceholder(): string {
  return COMPLIANCE_REDACTED;
}

function breakdown<T>(
  items: readonly T[],
  key: (item: T) => string,
): OpenPlatformComplianceCountBreakdown {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const bucket = key(item);
    counts[bucket] = (counts[bucket] ?? 0) + 1;
  }
  return {
    total: items.length,
    counts: Object.freeze(sortRecord(counts)),
  };
}

function distinctSubjects(records: readonly ComplianceConsentRecord[]): number {
  return new Set(records.map((record) => record.subjectRef)).size;
}

function oldestOpenDays(
  requests: readonly CompliancePrivacyRequest[],
  generatedAt: string,
): number {
  const now = Date.parse(generatedAt);
  let oldest = 0;
  for (const record of requests) {
    const days = Math.floor((now - Date.parse(record.createdAt)) / 86_400_000);
    if (days > oldest) oldest = days;
  }
  return oldest;
}

function gapOf(
  code: ComplianceReportGapCode,
  resourceIds: readonly string[],
): OpenPlatformComplianceReportGap | undefined {
  if (resourceIds.length === 0) return undefined;
  return {
    code,
    count: resourceIds.length,
    resourceIds: [...resourceIds].sort((left, right) =>
      left < right ? -1 : left > right ? 1 : 0,
    ),
  };
}

function sortRecord(
  value: Readonly<Record<string, number>>,
): Record<string, number> {
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    ),
  );
}

function deepFreezeReport(report: OpenPlatformComplianceReport): OpenPlatformComplianceReport {
  for (const value of Object.values(report)) {
    deepFreezeValue(value);
  }
  return Object.freeze(report);
}

function deepFreezeValue(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  for (const item of Object.values(value as Record<string, unknown>)) {
    deepFreezeValue(item);
  }
  Object.freeze(value);
}
