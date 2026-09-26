import {
  assertComplianceReportIsRedacted,
  redactComplianceValue,
} from "./redaction.js";
import type {
  OpenPlatformComplianceConsentRecordDto,
  OpenPlatformComplianceCrossBorderAssessmentDto,
  OpenPlatformComplianceDataAssetDto,
  OpenPlatformCompliancePrivacyRequestDto,
  OpenPlatformComplianceRetentionExecutionDto,
  OpenPlatformComplianceRetentionPolicyDto,
  OpenPlatformComplianceVendorDto,
} from "@getbrick/idaas-contracts";
import type {
  ComplianceConsentRecord,
  ComplianceCrossBorderAssessment,
  ComplianceDataAsset,
  CompliancePrivacyRequest,
  ComplianceRecord,
  ComplianceRetentionExecution,
  ComplianceRetentionPolicy,
  ComplianceVendor,
} from "./types.js";

export type ComplianceDataAssetDto = OpenPlatformComplianceDataAssetDto;
export type ComplianceConsentRecordDto = OpenPlatformComplianceConsentRecordDto;
export type CompliancePrivacyRequestDto = OpenPlatformCompliancePrivacyRequestDto;
export type ComplianceRetentionPolicyDto = OpenPlatformComplianceRetentionPolicyDto;
export type ComplianceRetentionExecutionDto = OpenPlatformComplianceRetentionExecutionDto;
export type ComplianceCrossBorderAssessmentDto = OpenPlatformComplianceCrossBorderAssessmentDto;
export type ComplianceVendorDto = OpenPlatformComplianceVendorDto;

export type ComplianceRecordDto =
  | ComplianceDataAssetDto
  | ComplianceConsentRecordDto
  | CompliancePrivacyRequestDto
  | ComplianceRetentionPolicyDto
  | ComplianceRetentionExecutionDto
  | ComplianceCrossBorderAssessmentDto
  | ComplianceVendorDto;

export function toComplianceDataAssetDto(
  record: ComplianceDataAsset,
): ComplianceDataAssetDto {
  return Object.freeze({
    ...record,
    purposes: [...record.purposes],
    categories: [...record.categories],
    dataSubjects: [...record.dataSubjects],
    residencyRegions: [...record.residencyRegions],
    evidence: record.evidence.map((item) => Object.freeze({ ...item })),
  }) as ComplianceDataAssetDto;
}

export function toComplianceConsentRecordDto(
  record: ComplianceConsentRecord,
): ComplianceConsentRecordDto {
  return Object.freeze({
    ...record,
    scopes: [...record.scopes],
    dataAssetIds: [...record.dataAssetIds],
    proof: record.proof.map((item) => Object.freeze({ ...item })),
  }) as ComplianceConsentRecordDto;
}

export function toCompliancePrivacyRequestDto(
  record: CompliancePrivacyRequest,
): CompliancePrivacyRequestDto {
  return Object.freeze({
    ...record,
    dataAssetIds: [...record.dataAssetIds],
    identityVerification: Object.freeze({
      ...record.identityVerification,
      evidence: record.identityVerification.evidence.map((item) =>
        Object.freeze({ ...item }),
      ),
    }),
    sla: Object.freeze({ ...record.sla }),
    ...(record.decision === undefined
      ? {}
      : {
        decision: Object.freeze({
          ...record.decision,
          evidence: record.decision.evidence.map((item) => Object.freeze({ ...item })),
        }),
      }),
    actions: record.actions.map((item) => Object.freeze({ ...item })),
  }) as CompliancePrivacyRequestDto;
}

export function toComplianceRetentionPolicyDto(
  record: ComplianceRetentionPolicy,
): ComplianceRetentionPolicyDto {
  return Object.freeze({
    ...record,
    dataAssetIds: [...record.dataAssetIds],
    residencyRegions: [...record.residencyRegions],
    evidence: record.evidence.map((item) => Object.freeze({ ...item })),
  }) as ComplianceRetentionPolicyDto;
}

export function toComplianceRetentionExecutionDto(
  record: ComplianceRetentionExecution,
): ComplianceRetentionExecutionDto {
  return Object.freeze({
    ...record,
    dataAssetIds: [...record.dataAssetIds],
    result: Object.freeze({
      ...record.result,
      evidence: record.result.evidence.map((item) => Object.freeze({ ...item })),
    }),
  }) as ComplianceRetentionExecutionDto;
}

export function toComplianceCrossBorderAssessmentDto(
  record: ComplianceCrossBorderAssessment,
): ComplianceCrossBorderAssessmentDto {
  return Object.freeze({
    ...record,
    destinationRegions: [...record.destinationRegions],
    dataAssetIds: [...record.dataAssetIds],
    riskFactors: [...record.riskFactors],
    mechanisms: [...record.mechanisms],
    evidence: record.evidence.map((item) => Object.freeze({ ...item })),
  }) as ComplianceCrossBorderAssessmentDto;
}

export function toComplianceVendorDto(record: ComplianceVendor): ComplianceVendorDto {
  return Object.freeze({
    ...record,
    regions: [...record.regions],
    dataAssetIds: [...record.dataAssetIds],
    dataCategories: [...record.dataCategories],
    assessment: Object.freeze({
      ...record.assessment,
      evidence: record.assessment.evidence.map((item) => Object.freeze({ ...item })),
    }),
    evidence: record.evidence.map((item) => Object.freeze({ ...item })),
  }) as ComplianceVendorDto;
}

export function toComplianceRecordDto(record: ComplianceRecord): ComplianceRecordDto {
  switch (record.kind) {
    case "dataAsset":
      return toComplianceDataAssetDto(record);
    case "consentRecord":
      return toComplianceConsentRecordDto(record);
    case "privacyRequest":
      return toCompliancePrivacyRequestDto(record);
    case "retentionPolicy":
      return toComplianceRetentionPolicyDto(record);
    case "retentionExecution":
      return toComplianceRetentionExecutionDto(record);
    case "crossBorderAssessment":
      return toComplianceCrossBorderAssessmentDto(record);
    case "vendor":
      return toComplianceVendorDto(record);
  }
}

export function redactComplianceFreeText(
  value: string | undefined,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  const redacted = redactComplianceValue(value, { field, maxDepth: 2 });
  return typeof redacted === "string" ? redacted : undefined;
}

export function assertComplianceDtoIsRedacted(dto: ComplianceRecordDto): void {
  assertComplianceReportIsRedacted(dto, "dto");
}
