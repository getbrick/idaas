import type {
  OpenPlatformComplianceConsentChannel,
  OpenPlatformComplianceConsentStatus,
  OpenPlatformComplianceConsentRecordDto,
  OpenPlatformComplianceCrossBorderAssessmentDto,
  OpenPlatformComplianceCrossBorderMechanism,
  OpenPlatformComplianceCrossBorderStatus,
  OpenPlatformComplianceDataAssetDto,
  OpenPlatformComplianceDataAssetStatus,
  OpenPlatformComplianceDataCategory,
  OpenPlatformComplianceDataClassification,
  OpenPlatformComplianceDataSubjectGroup,
  OpenPlatformComplianceEvidenceReference,
  OpenPlatformComplianceIdentityVerificationMethod,
  OpenPlatformComplianceIdentityVerificationStatus,
  OpenPlatformComplianceLegalBasis,
  OpenPlatformCompliancePrivacyRequestAction,
  OpenPlatformCompliancePrivacyRequestDecision,
  OpenPlatformCompliancePrivacyRequestDto,
  OpenPlatformCompliancePrivacyRequestStatus,
  OpenPlatformCompliancePrivacyRequestType,
  OpenPlatformComplianceReport,
  OpenPlatformComplianceRetentionAction,
  OpenPlatformComplianceRetentionExecutionDto,
  OpenPlatformComplianceRetentionExecutionStatus,
  OpenPlatformComplianceRetentionPolicyDto,
  OpenPlatformComplianceRetentionPolicyStatus,
  OpenPlatformComplianceRetentionTrigger,
  OpenPlatformComplianceRiskLevel,
  OpenPlatformComplianceVendorDto,
  OpenPlatformComplianceVendorRole,
} from "@getbrick/idaas-contracts";

export {
  OPEN_PLATFORM_COMPLIANCE_CONTRACT_VERSION,
  OPEN_PLATFORM_COMPLIANCE_REDACTED,
  OPEN_PLATFORM_COMPLIANCE_ENTITY_KINDS,
  OPEN_PLATFORM_COMPLIANCE_STATEFUL_ENTITY_KINDS,
  OPEN_PLATFORM_COMPLIANCE_DATA_CLASSIFICATIONS,
  OPEN_PLATFORM_COMPLIANCE_DATA_CATEGORIES,
  OPEN_PLATFORM_COMPLIANCE_SENSITIVE_DATA_CATEGORIES,
  OPEN_PLATFORM_COMPLIANCE_LEGAL_BASES,
  OPEN_PLATFORM_COMPLIANCE_DATA_SUBJECT_GROUPS,
  OPEN_PLATFORM_COMPLIANCE_DATA_ASSET_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_CONSENT_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_CONSENT_CHANNELS,
  OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TYPES,
  OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TERMINAL_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_METHODS,
  OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_DECISIONS,
  OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_ACTIONS,
  OPEN_PLATFORM_COMPLIANCE_SLA_STATES,
  OPEN_PLATFORM_COMPLIANCE_RETENTION_POLICY_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_RETENTION_TRIGGERS,
  OPEN_PLATFORM_COMPLIANCE_RETENTION_ACTIONS,
  OPEN_PLATFORM_COMPLIANCE_RETENTION_EXECUTION_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_RISK_LEVELS,
  OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_MECHANISMS,
  OPEN_PLATFORM_COMPLIANCE_VENDOR_ROLES,
  OPEN_PLATFORM_COMPLIANCE_VENDOR_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_ASSESSMENT_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_REPORT_GAP_CODES,
  OPEN_PLATFORM_COMPLIANCE_REPORT_LIMITATIONS,
  OPEN_PLATFORM_COMPLIANCE_ERROR_CODES,
  OPEN_PLATFORM_COMPLIANCE_ERROR_DEFINITIONS,
  OPEN_PLATFORM_COMPLIANCE_DEFAULT_PAGE_SIZE,
  OPEN_PLATFORM_COMPLIANCE_MAX_PAGE_SIZE,
  OPEN_PLATFORM_COMPLIANCE_TRANSITIONS,
  OPEN_PLATFORM_COMPLIANCE_DATA_ASSET_TRANSITIONS,
  OPEN_PLATFORM_COMPLIANCE_CONSENT_TRANSITIONS,
  OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TRANSITIONS,
  OPEN_PLATFORM_COMPLIANCE_RETENTION_POLICY_TRANSITIONS,
  OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_TRANSITIONS,
  OPEN_PLATFORM_COMPLIANCE_VENDOR_TRANSITIONS,
} from "@getbrick/idaas-contracts";
export type {
  OpenPlatformComplianceAssessmentStatus,
  OpenPlatformComplianceConsentRecordDto,
  OpenPlatformComplianceCountBreakdown,
  OpenPlatformComplianceCrossBorderAssessmentDto,
  OpenPlatformComplianceDataAssetDto,
  OpenPlatformComplianceEntityKind,
  OpenPlatformComplianceErrorCode,
  OpenPlatformComplianceErrorDefinition,
  OpenPlatformComplianceEvidenceReference,
  OpenPlatformComplianceIdentityVerificationDto,
  OpenPlatformComplianceListQuery as OpenPlatformComplianceContractListQuery,
  OpenPlatformCompliancePage as OpenPlatformComplianceContractPage,
  OpenPlatformCompliancePrivacyRequestActionDto,
  OpenPlatformCompliancePrivacyRequestDecisionDto,
  OpenPlatformCompliancePrivacyRequestDto,
  OpenPlatformCompliancePrivacyRequestSlaDto,
  OpenPlatformComplianceRedacted,
  OpenPlatformComplianceReference,
  OpenPlatformComplianceReport,
  OpenPlatformComplianceReportGap,
  OpenPlatformComplianceReportGapCode,
  OpenPlatformComplianceReportLimitation,
  OpenPlatformComplianceRetentionExecutionDto,
  OpenPlatformComplianceRetentionPolicyDto,
  OpenPlatformComplianceStatefulEntityKind,
  OpenPlatformComplianceVendorAssessmentDto,
  OpenPlatformComplianceVendorDto,
} from "@getbrick/idaas-contracts";

export const OPEN_PLATFORM_COMPLIANCE_BASE_PATH = "/compliance" as const;

export const OPEN_PLATFORM_COMPLIANCE_REDACTED_PLACEHOLDER = "[redacted]" as const;

export type OpenPlatformComplianceRedactedPlaceholder =
  typeof OPEN_PLATFORM_COMPLIANCE_REDACTED_PLACEHOLDER;

export type OpenPlatformComplianceSafeString = string;

export type OpenPlatformComplianceSafeReference = string;

const RAW_SUBJECT_KEYS = new Set([
  "subject",
  "subjectemail",
  "subjectid",
  "subjectname",
  "subjectphone",
  "subjectreference",
  "subjectref",
  "datasubjectemail",
  "datasubjectid",
  "datasubjectname",
  "datasubjectphone",
  "datasubjectref",
  "datasubjectreference",
]);

export function isRawOpenPlatformComplianceSubjectKey(key: string): boolean {
  return RAW_SUBJECT_KEYS.has(key.replace(/[-_]/gu, "").toLowerCase());
}

export function redactOpenPlatformComplianceSubjects<T>(value: T): T {
  return redactComplianceValue(value, new WeakSet<object>()) as T;
}

function redactComplianceValue(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return value;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) redactComplianceValue(item, seen);
    return value;
  }
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (isRawOpenPlatformComplianceSubjectKey(key)) {
      delete (value as Record<string, unknown>)[key];
      continue;
    }
    redactComplianceValue(nested, seen);
  }
  return value;
}

export type OpenPlatformComplianceEvidenceKind =
  OpenPlatformComplianceEvidenceReference["kind"];

export interface OpenPlatformComplianceEvidence extends OpenPlatformComplianceEvidenceReference {}

export type OpenPlatformComplianceDataAsset = OpenPlatformComplianceDataAssetDto & {
  readonly code: string;
};

export type OpenPlatformComplianceConsentRecord =
  Omit<OpenPlatformComplianceConsentRecordDto, "subjectRef"> & {
    readonly subjectRefMasked: string;
    readonly subjectCount: number;
  };

export type OpenPlatformCompliancePrivacyRequest =
  Omit<OpenPlatformCompliancePrivacyRequestDto, "subjectRef"> & {
    readonly subjectRefMasked: string;
  };

export type OpenPlatformCompliancePrivacyRequestSlaState =
  OpenPlatformCompliancePrivacyRequestDto["sla"]["state"];

export interface OpenPlatformCompliancePrivacyRequestSla {
  readonly id: string;
  readonly requestId: string;
  readonly requestType: OpenPlatformCompliancePrivacyRequestType;
  readonly status: OpenPlatformCompliancePrivacyRequestStatus;
  readonly policyCode: string;
  readonly responseDays: number;
  readonly dueAt: string;
  readonly respondedAt?: string;
  readonly closedAt?: string;
  readonly state: OpenPlatformCompliancePrivacyRequestSlaState;
  readonly millisecondsRemaining: number;
}

export type OpenPlatformComplianceRetentionPolicy =
  OpenPlatformComplianceRetentionPolicyDto & { readonly code: string };

export type OpenPlatformComplianceRetentionExecution =
  Omit<OpenPlatformComplianceRetentionExecutionDto, "result"> & {
    readonly recordsScanned: number;
    readonly recordsDeleted: number;
    readonly recordsAnonymized: number;
    readonly recordsArchived: number;
    readonly completedAt?: string;
    readonly failureReason?: string;
    readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
  };

export type OpenPlatformComplianceCrossBorderAssessment =
  OpenPlatformComplianceCrossBorderAssessmentDto & { readonly code: string };

export type OpenPlatformComplianceVendor = OpenPlatformComplianceVendorDto;

export type OpenPlatformComplianceReportView = OpenPlatformComplianceReport;

export interface OpenPlatformComplianceListQuery {
  readonly cursor?: string;
  readonly limit?: number | string;
  readonly pageSize?: number | string;
  readonly status?: string;
  readonly ids?: readonly string[];
  readonly tenantId?: string;
}

export type OpenPlatformComplianceDataAssetListQuery = OpenPlatformComplianceListQuery;
export type OpenPlatformComplianceConsentListQuery = OpenPlatformComplianceListQuery;
export type OpenPlatformCompliancePrivacyRequestListQuery = OpenPlatformComplianceListQuery;
export type OpenPlatformComplianceRetentionPolicyListQuery = OpenPlatformComplianceListQuery;
export type OpenPlatformComplianceRetentionExecutionListQuery = OpenPlatformComplianceListQuery;
export type OpenPlatformComplianceCrossBorderAssessmentListQuery = OpenPlatformComplianceListQuery;
export type OpenPlatformComplianceVendorListQuery = OpenPlatformComplianceListQuery;

export interface OpenPlatformComplianceReportQuery {
  readonly from?: string;
  readonly to?: string;
  readonly generatedAt?: string;
  readonly tenantId?: string;
}

export interface OpenPlatformComplianceMutationInput {
  readonly tenantId?: string;
  readonly idempotencyKey?: string;
}

export interface CreateOpenPlatformComplianceDataAssetInput
  extends OpenPlatformComplianceMutationInput {
  readonly name: string;
  readonly code: string;
  readonly classification: OpenPlatformComplianceDataClassification | string;
  readonly categories: readonly (OpenPlatformComplianceDataCategory | string)[];
  readonly personalData: boolean;
  readonly sensitivePersonalData: boolean;
  readonly residencyRegions: readonly string[];
  readonly crossBorder: boolean;
  readonly legalBasis?: OpenPlatformComplianceLegalBasis | string;
  readonly purposes?: readonly string[];
  readonly dataSubjects?: readonly (OpenPlatformComplianceDataSubjectGroup | string)[];
  readonly processorVendorId?: string;
  readonly retentionPolicyId?: string;
  readonly retentionDays?: number;
  readonly evidence?: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface UpdateOpenPlatformComplianceDataAssetInput
  extends OpenPlatformComplianceMutationInput {
  readonly name?: string;
  readonly classification?: OpenPlatformComplianceDataClassification | string;
  readonly categories?: readonly (OpenPlatformComplianceDataCategory | string)[];
  readonly legalBasis?: OpenPlatformComplianceLegalBasis | string | null;
  readonly purposes?: readonly string[];
  readonly dataSubjects?: readonly (OpenPlatformComplianceDataSubjectGroup | string)[];
  readonly residencyRegions?: readonly string[];
  readonly processorVendorId?: string | null;
  readonly retentionPolicyId?: string | null;
  readonly retentionDays?: number | null;
  readonly crossBorder?: boolean;
  readonly evidence?: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface TransitionOpenPlatformComplianceDataAssetInput
  extends OpenPlatformComplianceMutationInput {
  readonly targetStatus: OpenPlatformComplianceDataAssetStatus | string;
  readonly statusReason?: string;
}

export interface CreateOpenPlatformComplianceConsentRecordInput
  extends OpenPlatformComplianceMutationInput {
  readonly subjectRef: string;
  readonly purpose: string;
  readonly policyVersion: string;
  readonly channel: OpenPlatformComplianceConsentChannel | string;
  readonly subjectCount?: number;
  readonly language?: string;
  readonly scopes?: readonly string[];
  readonly dataAssetIds?: readonly string[];
  readonly expiresAt?: string;
  readonly status?: OpenPlatformComplianceConsentStatus | string;
  readonly grantedAt?: string;
  readonly proof?: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface GrantOpenPlatformComplianceConsentInput
  extends OpenPlatformComplianceMutationInput {
  readonly proof: readonly OpenPlatformComplianceEvidenceReference[];
  readonly grantedAt?: string;
  readonly expiresAt?: string;
}

export interface WithdrawOpenPlatformComplianceConsentInput
  extends OpenPlatformComplianceMutationInput {
  readonly withdrawnAt?: string;
  readonly reason?: string;
  readonly proof?: readonly OpenPlatformComplianceEvidenceReference[];
}

export type ExpireOpenPlatformComplianceConsentInput =
  OpenPlatformComplianceMutationInput;

export interface CreateOpenPlatformCompliancePrivacyRequestInput
  extends OpenPlatformComplianceMutationInput {
  readonly requestType: OpenPlatformCompliancePrivacyRequestType | string;
  readonly subjectRef: string;
  readonly subjectCount?: number;
  readonly dataAssetIds?: readonly string[];
  readonly receivedAt?: string;
  readonly responseDays?: number;
  readonly policyCode?: string;
  readonly duplicateOfId?: string;
}

export interface RecordOpenPlatformComplianceIdentityVerificationInput
  extends OpenPlatformComplianceMutationInput {
  readonly status: OpenPlatformComplianceIdentityVerificationStatus | string;
  readonly method?: OpenPlatformComplianceIdentityVerificationMethod | string;
  readonly verifiedByRef?: string;
  readonly evidence?: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface DecideOpenPlatformCompliancePrivacyRequestInput
  extends OpenPlatformComplianceMutationInput {
  readonly decision: OpenPlatformCompliancePrivacyRequestDecision | string;
  readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
  readonly rationale?: string;
  readonly targetStatus?: OpenPlatformCompliancePrivacyRequestStatus | string;
}

export interface RecordOpenPlatformCompliancePrivacyRequestActionInput
  extends OpenPlatformComplianceMutationInput {
  readonly action: OpenPlatformCompliancePrivacyRequestAction | string;
  readonly dataAssetId: string;
  readonly executedAt?: string;
  readonly affectedRecords?: number;
  readonly executionRef?: string;
}

export interface TransitionOpenPlatformCompliancePrivacyRequestInput
  extends OpenPlatformComplianceMutationInput {
  readonly targetStatus: OpenPlatformCompliancePrivacyRequestStatus | string;
  readonly statusReason?: string;
}

export interface CreateOpenPlatformComplianceRetentionPolicyInput
  extends OpenPlatformComplianceMutationInput {
  readonly name: string;
  readonly code: string;
  readonly trigger: OpenPlatformComplianceRetentionTrigger | string;
  readonly action: OpenPlatformComplianceRetentionAction | string;
  readonly retentionDays: number;
  readonly requiresApproval: boolean;
  readonly legalHold: boolean;
  readonly dataAssetIds?: readonly string[];
  readonly residencyRegions?: readonly string[];
  readonly evidence?: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface TransitionOpenPlatformComplianceRetentionPolicyInput
  extends OpenPlatformComplianceMutationInput {
  readonly targetStatus: OpenPlatformComplianceRetentionPolicyStatus | string;
  readonly statusReason?: string;
}

export interface RecordOpenPlatformComplianceRetentionExecutionInput
  extends OpenPlatformComplianceMutationInput {
  readonly policyId: string;
  readonly status: OpenPlatformComplianceRetentionExecutionStatus | string;
  readonly runId?: string;
  readonly dataAssetIds?: readonly string[];
  readonly action?: OpenPlatformComplianceRetentionAction | string;
  readonly occurredAt?: string;
  readonly blockedReason?: string;
  readonly recordsScanned?: number;
  readonly recordsDeleted?: number;
  readonly recordsAnonymized?: number;
  readonly recordsArchived?: number;
  readonly completedAt?: string;
  readonly failureReason?: string;
  readonly evidence?: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface CreateOpenPlatformComplianceCrossBorderAssessmentInput
  extends OpenPlatformComplianceMutationInput {
  readonly title: string;
  readonly code: string;
  readonly sourceRegion: string;
  readonly destinationRegions: readonly string[];
  readonly transferPurpose: string;
  readonly dataAssetIds?: readonly string[];
  readonly personalData?: boolean;
  readonly sensitivePersonalData?: boolean;
  readonly riskLevel?: OpenPlatformComplianceRiskLevel | string;
  readonly riskFactors?: readonly string[];
  readonly mechanisms?: readonly (OpenPlatformComplianceCrossBorderMechanism | string)[];
  readonly recipientVendorId?: string;
  readonly validUntil?: string;
  readonly evidence?: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface TransitionOpenPlatformComplianceCrossBorderAssessmentInput
  extends OpenPlatformComplianceMutationInput {
  readonly targetStatus: OpenPlatformComplianceCrossBorderStatus | string;
  readonly statusReason?: string;
  readonly riskLevel?: OpenPlatformComplianceRiskLevel | string;
  readonly riskFactors?: readonly string[];
  readonly mechanisms?: readonly (OpenPlatformComplianceCrossBorderMechanism | string)[];
  readonly evidence?: readonly OpenPlatformComplianceEvidenceReference[];
  readonly validUntil?: string;
}

export interface CreateOpenPlatformComplianceVendorInput
  extends OpenPlatformComplianceMutationInput {
  readonly role: OpenPlatformComplianceVendorRole | string;
  readonly code: string;
  readonly legalName: string;
  readonly regions: readonly string[];
  readonly displayName?: string;
  readonly dataAssetIds?: readonly string[];
  readonly dataCategories?: readonly (OpenPlatformComplianceDataCategory | string)[];
  readonly parentVendorId?: string;
  readonly crossBorder?: boolean;
  readonly contractEffectiveAt?: string;
  readonly evidence?: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface TransitionOpenPlatformComplianceVendorInput
  extends OpenPlatformComplianceMutationInput {
  readonly targetStatus: string;
  readonly statusReason?: string;
  readonly contractTerminatedAt?: string;
}

export interface RecordOpenPlatformComplianceVendorAssessmentInput
  extends OpenPlatformComplianceMutationInput {
  readonly status: string;
  readonly assessedByRef?: string;
  readonly evidence?: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface GenerateOpenPlatformComplianceReportInput
  extends OpenPlatformComplianceMutationInput {
  readonly from?: string;
  readonly to?: string;
  readonly generatedAt?: string;
}

export type ComplianceDataAsset = OpenPlatformComplianceDataAsset;
export type ComplianceConsentRecord = OpenPlatformComplianceConsentRecord;
export type CompliancePrivacyRequest = OpenPlatformCompliancePrivacyRequest;
export type CompliancePrivacyRequestSla = OpenPlatformCompliancePrivacyRequestSla;
export type ComplianceRetentionPolicy = OpenPlatformComplianceRetentionPolicy;
export type ComplianceRetentionExecution = OpenPlatformComplianceRetentionExecution;
export type ComplianceCrossBorderAssessment = OpenPlatformComplianceCrossBorderAssessment;
export type ComplianceVendor = OpenPlatformComplianceVendor;
export type ComplianceReport = OpenPlatformComplianceReportView;
export type ComplianceEvidence = OpenPlatformComplianceEvidence;
export type ComplianceListQuery = OpenPlatformComplianceListQuery;
export type ComplianceReportQuery = OpenPlatformComplianceReportQuery;
