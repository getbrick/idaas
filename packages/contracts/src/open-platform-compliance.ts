export const OPEN_PLATFORM_COMPLIANCE_CONTRACT_VERSION = 1 as const;

export const OPEN_PLATFORM_COMPLIANCE_REDACTED = "[redacted]" as const;
export type OpenPlatformComplianceRedacted = typeof OPEN_PLATFORM_COMPLIANCE_REDACTED;

export const OPEN_PLATFORM_COMPLIANCE_ENTITY_KINDS = [
  "dataAsset",
  "consentRecord",
  "privacyRequest",
  "retentionPolicy",
  "retentionExecution",
  "crossBorderAssessment",
  "vendor",
] as const;
export type OpenPlatformComplianceEntityKind =
  (typeof OPEN_PLATFORM_COMPLIANCE_ENTITY_KINDS)[number];

export const OPEN_PLATFORM_COMPLIANCE_STATEFUL_ENTITY_KINDS = [
  "dataAsset",
  "consentRecord",
  "privacyRequest",
  "retentionPolicy",
  "crossBorderAssessment",
  "vendor",
] as const;
export type OpenPlatformComplianceStatefulEntityKind =
  (typeof OPEN_PLATFORM_COMPLIANCE_STATEFUL_ENTITY_KINDS)[number];

export const OPEN_PLATFORM_COMPLIANCE_DATA_CLASSIFICATIONS = [
  "internal",
  "confidential",
  "personal",
  "sensitivePersonal",
] as const;
export type OpenPlatformComplianceDataClassification =
  (typeof OPEN_PLATFORM_COMPLIANCE_DATA_CLASSIFICATIONS)[number];

export const OPEN_PLATFORM_COMPLIANCE_DATA_CATEGORIES = [
  "identity",
  "contact",
  "credential",
  "biometric",
  "financial",
  "location",
  "device",
  "employment",
  "health",
  "usage",
  "other",
] as const;
export type OpenPlatformComplianceDataCategory =
  (typeof OPEN_PLATFORM_COMPLIANCE_DATA_CATEGORIES)[number];

export const OPEN_PLATFORM_COMPLIANCE_SENSITIVE_DATA_CATEGORIES = [
  "biometric",
  "financial",
  "health",
] as const;
export type OpenPlatformComplianceSensitiveDataCategory =
  (typeof OPEN_PLATFORM_COMPLIANCE_SENSITIVE_DATA_CATEGORIES)[number];

export const OPEN_PLATFORM_COMPLIANCE_LEGAL_BASES = [
  "consent",
  "contract",
  "legalObligation",
  "legitimateInterest",
  "other",
] as const;
export type OpenPlatformComplianceLegalBasis =
  (typeof OPEN_PLATFORM_COMPLIANCE_LEGAL_BASES)[number];

export const OPEN_PLATFORM_COMPLIANCE_DATA_SUBJECT_GROUPS = [
  "customer",
  "employee",
  "partner",
  "visitor",
  "prospect",
  "other",
] as const;
export type OpenPlatformComplianceDataSubjectGroup =
  (typeof OPEN_PLATFORM_COMPLIANCE_DATA_SUBJECT_GROUPS)[number];

export const OPEN_PLATFORM_COMPLIANCE_DATA_ASSET_STATUSES = [
  "draft",
  "registered",
  "active",
  "retired",
] as const;
export type OpenPlatformComplianceDataAssetStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_DATA_ASSET_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_CONSENT_STATUSES = [
  "pending",
  "granted",
  "withdrawn",
  "expired",
] as const;
export type OpenPlatformComplianceConsentStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_CONSENT_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_CONSENT_CHANNELS = [
  "web",
  "app",
  "api",
  "offline",
  "import",
] as const;
export type OpenPlatformComplianceConsentChannel =
  (typeof OPEN_PLATFORM_COMPLIANCE_CONSENT_CHANNELS)[number];

export const OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TYPES = [
  "access",
  "deletion",
  "correction",
  "revocation",
  "portability",
] as const;
export type OpenPlatformCompliancePrivacyRequestType =
  (typeof OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TYPES)[number];

export const OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_STATUSES = [
  "submitted",
  "verifyingIdentity",
  "verified",
  "inProgress",
  "fulfilled",
  "partiallyFulfilled",
  "rejected",
  "cancelled",
] as const;
export type OpenPlatformCompliancePrivacyRequestStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TERMINAL_STATUSES = [
  "fulfilled",
  "partiallyFulfilled",
  "rejected",
  "cancelled",
] as const;
export type OpenPlatformCompliancePrivacyRequestTerminalStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TERMINAL_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_STATUSES = [
  "notStarted",
  "pending",
  "verified",
  "failed",
] as const;
export type OpenPlatformComplianceIdentityVerificationStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_METHODS = [
  "inSession",
  "reauthentication",
  "documentReview",
  "offlineManual",
  "trustedThirdParty",
] as const;
export type OpenPlatformComplianceIdentityVerificationMethod =
  (typeof OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_METHODS)[number];

export const OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_DECISIONS = [
  "granted",
  "partiallyGranted",
  "denied",
] as const;
export type OpenPlatformCompliancePrivacyRequestDecision =
  (typeof OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_DECISIONS)[number];

export const OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_ACTIONS = [
  "exported",
  "erased",
  "corrected",
  "revoked",
] as const;
export type OpenPlatformCompliancePrivacyRequestAction =
  (typeof OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_ACTIONS)[number];

export const OPEN_PLATFORM_COMPLIANCE_SLA_STATES = [
  "withinSla",
  "dueSoon",
  "breached",
  "closedMet",
  "closedBreached",
] as const;
export type OpenPlatformComplianceSlaState =
  (typeof OPEN_PLATFORM_COMPLIANCE_SLA_STATES)[number];

export const OPEN_PLATFORM_COMPLIANCE_RETENTION_POLICY_STATUSES = [
  "draft",
  "active",
  "superseded",
  "retired",
] as const;
export type OpenPlatformComplianceRetentionPolicyStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_RETENTION_POLICY_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_RETENTION_TRIGGERS = [
  "time",
  "event",
  "manual",
] as const;
export type OpenPlatformComplianceRetentionTrigger =
  (typeof OPEN_PLATFORM_COMPLIANCE_RETENTION_TRIGGERS)[number];

export const OPEN_PLATFORM_COMPLIANCE_RETENTION_ACTIONS = [
  "delete",
  "anonymize",
  "archive",
  "review",
] as const;
export type OpenPlatformComplianceRetentionAction =
  (typeof OPEN_PLATFORM_COMPLIANCE_RETENTION_ACTIONS)[number];

export const OPEN_PLATFORM_COMPLIANCE_RETENTION_EXECUTION_STATUSES = [
  "planned",
  "running",
  "completed",
  "failed",
  "skipped",
  "blocked",
] as const;
export type OpenPlatformComplianceRetentionExecutionStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_RETENTION_EXECUTION_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_STATUSES = [
  "draft",
  "assessing",
  "pendingApproval",
  "approved",
  "rejected",
  "expired",
  "withdrawn",
] as const;
export type OpenPlatformComplianceCrossBorderStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_RISK_LEVELS = [
  "low",
  "medium",
  "high",
  "critical",
] as const;
export type OpenPlatformComplianceRiskLevel =
  (typeof OPEN_PLATFORM_COMPLIANCE_RISK_LEVELS)[number];

export const OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_MECHANISMS = [
  "securityAssessment",
  "standardContract",
  "certification",
  "explicitConsent",
  "other",
] as const;
export type OpenPlatformComplianceCrossBorderMechanism =
  (typeof OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_MECHANISMS)[number];

export const OPEN_PLATFORM_COMPLIANCE_VENDOR_ROLES = [
  "processor",
  "subProcessor",
] as const;
export type OpenPlatformComplianceVendorRole =
  (typeof OPEN_PLATFORM_COMPLIANCE_VENDOR_ROLES)[number];

export const OPEN_PLATFORM_COMPLIANCE_VENDOR_STATUSES = [
  "draft",
  "pendingAssessment",
  "active",
  "suspended",
  "terminated",
] as const;
export type OpenPlatformComplianceVendorStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_VENDOR_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_ASSESSMENT_STATUSES = [
  "notStarted",
  "inProgress",
  "passed",
  "failed",
  "expired",
] as const;
export type OpenPlatformComplianceAssessmentStatus =
  (typeof OPEN_PLATFORM_COMPLIANCE_ASSESSMENT_STATUSES)[number];

export const OPEN_PLATFORM_COMPLIANCE_REPORT_GAP_CODES = [
  "dataAssetWithoutPurpose",
  "dataAssetWithoutRetentionPolicy",
  "sensitiveDataAssetWithoutLegalBasis",
  "consentWithdrawnWhileAssetActive",
  "privacyRequestWithoutIdentityVerification",
  "privacyRequestSlaBreached",
  "retentionExecutionFailed",
  "crossBorderWithoutMechanism",
  "crossBorderAwaitingDecision",
  "vendorAssessmentIncomplete",
  "subProcessorWithoutParent",
] as const;
export type OpenPlatformComplianceReportGapCode =
  (typeof OPEN_PLATFORM_COMPLIANCE_REPORT_GAP_CODES)[number];

export const OPEN_PLATFORM_COMPLIANCE_ERROR_CODES = {
  VALIDATION_ERROR: "OPEN_PLATFORM_COMPLIANCE_VALIDATION_ERROR",
  RESOURCE_NOT_FOUND: "OPEN_PLATFORM_COMPLIANCE_RESOURCE_NOT_FOUND",
  RESOURCE_CONFLICT: "OPEN_PLATFORM_COMPLIANCE_RESOURCE_CONFLICT",
  INVALID_STATE_TRANSITION: "OPEN_PLATFORM_COMPLIANCE_INVALID_STATE_TRANSITION",
  IMMUTABLE_RECORD: "OPEN_PLATFORM_COMPLIANCE_IMMUTABLE_RECORD",
  TENANT_MISMATCH: "OPEN_PLATFORM_COMPLIANCE_TENANT_MISMATCH",
  IDENTITY_VERIFICATION_REQUIRED:
    "OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_REQUIRED",
  LEGAL_BASIS_REQUIRED: "OPEN_PLATFORM_COMPLIANCE_LEGAL_BASIS_REQUIRED",
  CROSS_BORDER_MECHANISM_REQUIRED:
    "OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_MECHANISM_REQUIRED",
  REDACTION_FAILED: "OPEN_PLATFORM_COMPLIANCE_REDACTION_FAILED",
  STORAGE_UNAVAILABLE: "OPEN_PLATFORM_COMPLIANCE_STORAGE_UNAVAILABLE",
} as const;
export type OpenPlatformComplianceErrorCode =
  (typeof OPEN_PLATFORM_COMPLIANCE_ERROR_CODES)[keyof typeof OPEN_PLATFORM_COMPLIANCE_ERROR_CODES];

export interface OpenPlatformComplianceErrorDefinition {
  readonly status: number;
  readonly retryable: boolean;
  readonly message: string;
}

export const OPEN_PLATFORM_COMPLIANCE_ERROR_DEFINITIONS = {
  OPEN_PLATFORM_COMPLIANCE_VALIDATION_ERROR: {
    status: 400,
    retryable: false,
    message: "The compliance request is invalid.",
  },
  OPEN_PLATFORM_COMPLIANCE_RESOURCE_NOT_FOUND: {
    status: 404,
    retryable: false,
    message: "The compliance resource was not found.",
  },
  OPEN_PLATFORM_COMPLIANCE_RESOURCE_CONFLICT: {
    status: 409,
    retryable: false,
    message: "The compliance resource conflicts with existing state.",
  },
  OPEN_PLATFORM_COMPLIANCE_INVALID_STATE_TRANSITION: {
    status: 409,
    retryable: false,
    message: "The compliance state transition is not allowed.",
  },
  OPEN_PLATFORM_COMPLIANCE_IMMUTABLE_RECORD: {
    status: 409,
    retryable: false,
    message: "The compliance record is immutable.",
  },
  OPEN_PLATFORM_COMPLIANCE_TENANT_MISMATCH: {
    status: 403,
    retryable: false,
    message: "The compliance resource is outside the tenant boundary.",
  },
  OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_REQUIRED: {
    status: 409,
    retryable: false,
    message: "Identity verification evidence is required.",
  },
  OPEN_PLATFORM_COMPLIANCE_LEGAL_BASIS_REQUIRED: {
    status: 409,
    retryable: false,
    message: "A recorded legal basis is required.",
  },
  OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_MECHANISM_REQUIRED: {
    status: 409,
    retryable: false,
    message: "A recorded cross-border legal mechanism is required.",
  },
  OPEN_PLATFORM_COMPLIANCE_REDACTION_FAILED: {
    status: 500,
    retryable: false,
    message: "Sensitive fields could not be redacted.",
  },
  OPEN_PLATFORM_COMPLIANCE_STORAGE_UNAVAILABLE: {
    status: 503,
    retryable: true,
    message: "Compliance storage is unavailable.",
  },
} as const satisfies Record<
  OpenPlatformComplianceErrorCode,
  OpenPlatformComplianceErrorDefinition
>;

export class OpenPlatformComplianceContractError extends Error {
  readonly code: OpenPlatformComplianceErrorCode;
  readonly status: number;
  readonly retryable: boolean;
  readonly field: string | undefined;

  constructor(code: OpenPlatformComplianceErrorCode, field?: string) {
    const definition = OPEN_PLATFORM_COMPLIANCE_ERROR_DEFINITIONS[code];
    super(definition.message);
    this.name = "OpenPlatformComplianceContractError";
    this.code = code;
    this.status = definition.status;
    this.retryable = definition.retryable;
    this.field = sanitizeOpenPlatformComplianceErrorField(field);
  }
}

export function createOpenPlatformComplianceError(
  code: OpenPlatformComplianceErrorCode,
  field?: string,
): OpenPlatformComplianceErrorDefinition & {
  readonly code: OpenPlatformComplianceErrorCode;
  readonly field?: string;
} {
  const definition = OPEN_PLATFORM_COMPLIANCE_ERROR_DEFINITIONS[code];
  const safeField = sanitizeOpenPlatformComplianceErrorField(field);
  return {
    ...definition,
    code,
    ...(safeField === undefined ? {} : { field: safeField }),
  };
}

export function isOpenPlatformComplianceErrorCode(
  value: unknown,
): value is OpenPlatformComplianceErrorCode {
  return (
    typeof value === "string" &&
    (Object.values(OPEN_PLATFORM_COMPLIANCE_ERROR_CODES) as readonly string[]).includes(
      value,
    )
  );
}

export const OPEN_PLATFORM_COMPLIANCE_DEFAULT_PAGE_SIZE = 20 as const;
export const OPEN_PLATFORM_COMPLIANCE_MAX_PAGE_SIZE = 100 as const;

export interface OpenPlatformCompliancePageRequest {
  readonly cursor?: string;
  readonly limit?: number | string;
}

export interface OpenPlatformComplianceListQuery extends OpenPlatformCompliancePageRequest {
  readonly tenantId: string;
  readonly status?: string;
  readonly ids?: readonly string[];
}

export interface OpenPlatformCompliancePage<T> {
  readonly items: readonly T[];
  readonly nextCursor?: string;
  readonly hasMore: boolean;
  readonly total: number;
}

export interface OpenPlatformComplianceReference {
  readonly id: string;
  readonly kind: OpenPlatformComplianceEntityKind;
  readonly status: string;
}

export interface OpenPlatformComplianceEvidenceReference {
  readonly reference: string;
  readonly kind: "document" | "systemRecord" | "ticket" | "attestation";
  readonly recordedAt?: string;
}

export interface OpenPlatformComplianceDataAssetDto {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "dataAsset";
  readonly version: number;
  readonly name: string;
  readonly status: OpenPlatformComplianceDataAssetStatus;
  readonly classification: OpenPlatformComplianceDataClassification;
  readonly categories: readonly OpenPlatformComplianceDataCategory[];
  readonly personalData: boolean;
  readonly sensitivePersonalData: boolean;
  readonly legalBasis?: OpenPlatformComplianceLegalBasis;
  readonly purposes: readonly string[];
  readonly dataSubjects: readonly OpenPlatformComplianceDataSubjectGroup[];
  readonly residencyRegions: readonly string[];
  readonly processorVendorId?: string;
  readonly retentionPolicyId?: string;
  readonly retentionDays?: number;
  readonly crossBorder: boolean;
  readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface OpenPlatformComplianceConsentRecordDto {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "consentRecord";
  readonly version: number;
  readonly status: OpenPlatformComplianceConsentStatus;
  readonly subjectRef: string;
  readonly purpose: string;
  readonly legalBasis: "consent";
  readonly policyVersion: string;
  readonly channel: OpenPlatformComplianceConsentChannel;
  readonly language?: string;
  readonly scopes: readonly string[];
  readonly dataAssetIds: readonly string[];
  readonly grantedAt?: string;
  readonly withdrawnAt?: string;
  readonly expiresAt?: string;
  readonly withdrawalReason?: string;
  readonly proof: readonly OpenPlatformComplianceEvidenceReference[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface OpenPlatformComplianceIdentityVerificationDto {
  readonly status: OpenPlatformComplianceIdentityVerificationStatus;
  readonly method?: OpenPlatformComplianceIdentityVerificationMethod;
  readonly attempts: number;
  readonly verifiedAt?: string;
  readonly verifiedByRef?: string;
  readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface OpenPlatformCompliancePrivacyRequestSlaDto {
  readonly policyCode: string;
  readonly responseDays: number;
  readonly dueAt: string;
  readonly respondedAt?: string;
  readonly closedAt?: string;
  readonly state: OpenPlatformComplianceSlaState;
}

export interface OpenPlatformCompliancePrivacyRequestDecisionDto {
  readonly decision: OpenPlatformCompliancePrivacyRequestDecision;
  readonly decidedAt: string;
  readonly decidedByRef: string;
  readonly rationale?: string;
  readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface OpenPlatformCompliancePrivacyRequestActionDto {
  readonly action: OpenPlatformCompliancePrivacyRequestAction;
  readonly dataAssetId: string;
  readonly executedAt: string;
  readonly affectedRecords?: number;
  readonly executionRef?: string;
}

export interface OpenPlatformCompliancePrivacyRequestDto {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "privacyRequest";
  readonly version: number;
  readonly requestType: OpenPlatformCompliancePrivacyRequestType;
  readonly status: OpenPlatformCompliancePrivacyRequestStatus;
  readonly subjectRef: string;
  readonly subjectCount: number;
  readonly statusReason?: string;
  readonly dataAssetIds: readonly string[];
  readonly identityVerification: OpenPlatformComplianceIdentityVerificationDto;
  readonly sla: OpenPlatformCompliancePrivacyRequestSlaDto;
  readonly decision?: OpenPlatformCompliancePrivacyRequestDecisionDto;
  readonly actions: readonly OpenPlatformCompliancePrivacyRequestActionDto[];
  readonly duplicateOfId?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface OpenPlatformComplianceRetentionPolicyDto {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "retentionPolicy";
  readonly version: number;
  readonly name: string;
  readonly status: OpenPlatformComplianceRetentionPolicyStatus;
  readonly trigger: OpenPlatformComplianceRetentionTrigger;
  readonly action: OpenPlatformComplianceRetentionAction;
  readonly retentionDays: number;
  readonly requiresApproval: boolean;
  readonly legalHold: boolean;
  readonly dataAssetIds: readonly string[];
  readonly residencyRegions: readonly string[];
  readonly lastExecutionId?: string;
  readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface OpenPlatformComplianceRetentionExecutionResultDto {
  readonly recordsScanned: number;
  readonly recordsDeleted: number;
  readonly recordsAnonymized: number;
  readonly recordsArchived: number;
  readonly completedAt?: string;
  readonly failureReason?: string;
  readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface OpenPlatformComplianceRetentionExecutionDto {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "retentionExecution";
  readonly version: 1;
  readonly policyId: string;
  readonly dataAssetIds: readonly string[];
  readonly status: OpenPlatformComplianceRetentionExecutionStatus;
  readonly action: OpenPlatformComplianceRetentionAction;
  readonly runId: string;
  readonly blockedReason?: string;
  readonly result: OpenPlatformComplianceRetentionExecutionResultDto;
  readonly recordedByRef: string;
  readonly occurredAt: string;
  readonly createdAt: string;
}

export interface OpenPlatformComplianceCrossBorderAssessmentDto {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "crossBorderAssessment";
  readonly version: number;
  readonly title: string;
  readonly status: OpenPlatformComplianceCrossBorderStatus;
  readonly sourceRegion: string;
  readonly destinationRegions: readonly string[];
  readonly transferPurpose: string;
  readonly dataAssetIds: readonly string[];
  readonly personalData: boolean;
  readonly sensitivePersonalData: boolean;
  readonly riskLevel: OpenPlatformComplianceRiskLevel;
  readonly riskFactors: readonly string[];
  readonly mechanisms: readonly OpenPlatformComplianceCrossBorderMechanism[];
  readonly recipientVendorId?: string;
  readonly decidedAt?: string;
  readonly decidedByRef?: string;
  readonly validUntil?: string;
  readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface OpenPlatformComplianceVendorAssessmentDto {
  readonly status: OpenPlatformComplianceAssessmentStatus;
  readonly assessedAt?: string;
  readonly assessedByRef?: string;
  readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
}

export interface OpenPlatformComplianceVendorDto {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "vendor";
  readonly version: number;
  readonly role: OpenPlatformComplianceVendorRole;
  readonly status: OpenPlatformComplianceVendorStatus;
  readonly code: string;
  readonly legalName: string;
  readonly displayName?: string;
  readonly regions: readonly string[];
  readonly dataAssetIds: readonly string[];
  readonly dataCategories: readonly OpenPlatformComplianceDataCategory[];
  readonly parentVendorId?: string;
  readonly crossBorder: boolean;
  readonly contractEffectiveAt?: string;
  readonly contractTerminatedAt?: string;
  readonly assessment: OpenPlatformComplianceVendorAssessmentDto;
  readonly evidence: readonly OpenPlatformComplianceEvidenceReference[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface OpenPlatformComplianceReportGap {
  readonly code: OpenPlatformComplianceReportGapCode;
  readonly count: number;
  readonly resourceIds: readonly string[];
}

export interface OpenPlatformComplianceCountBreakdown {
  readonly total: number;
  readonly counts: Readonly<Record<string, number>>;
}

export interface OpenPlatformComplianceReport {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly generatedAt: string;
  readonly period: {
    readonly from: string;
    readonly to: string;
  };
  readonly redaction: {
    readonly placeholder: OpenPlatformComplianceRedacted;
    readonly applies: true;
  };
  readonly dataCatalog: {
    readonly assets: OpenPlatformComplianceCountBreakdown;
    readonly byClassification: OpenPlatformComplianceCountBreakdown;
    readonly personalDataAssets: number;
    readonly sensitivePersonalDataAssets: number;
    readonly crossBorderAssets: number;
    readonly withoutPurpose: readonly string[];
    readonly withoutRetentionPolicy: readonly string[];
  };
  readonly consent: {
    readonly records: OpenPlatformComplianceCountBreakdown;
    readonly activeSubjects: number;
    readonly withdrawnSubjects: number;
    readonly withdrawnProofCount: number;
  };
  readonly privacyRequests: {
    readonly requests: OpenPlatformComplianceCountBreakdown;
    readonly awaitingIdentityVerification: number;
    readonly fulfilledWithinSla: number;
    readonly breached: number;
    readonly oldestOpenDays: number;
  };
  readonly retention: {
    readonly policies: OpenPlatformComplianceCountBreakdown;
    readonly executions: OpenPlatformComplianceCountBreakdown;
    readonly recordsDeleted: number;
    readonly recordsAnonymized: number;
    readonly failedExecutions: readonly string[];
  };
  readonly crossBorder: {
    readonly assessments: OpenPlatformComplianceCountBreakdown;
    readonly byRiskLevel: OpenPlatformComplianceCountBreakdown;
    readonly withoutMechanism: readonly string[];
    readonly awaitingDecision: readonly string[];
  };
  readonly vendors: {
    readonly vendors: OpenPlatformComplianceCountBreakdown;
    readonly byRole: OpenPlatformComplianceCountBreakdown;
    readonly assessment: OpenPlatformComplianceCountBreakdown;
    readonly regions: readonly string[];
  };
  readonly gaps: readonly OpenPlatformComplianceReportGap[];
  readonly limitations: readonly string[];
}

export const OPEN_PLATFORM_COMPLIANCE_DATA_ASSET_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["registered", "retired"]),
  registered: Object.freeze(["active", "retired"]),
  active: Object.freeze(["retired"]),
  retired: Object.freeze([]),
} as const satisfies Readonly<
  Record<
    OpenPlatformComplianceDataAssetStatus,
    readonly OpenPlatformComplianceDataAssetStatus[]
  >
>);

export const OPEN_PLATFORM_COMPLIANCE_CONSENT_TRANSITIONS = Object.freeze({
  pending: Object.freeze(["granted", "withdrawn"]),
  granted: Object.freeze(["withdrawn", "expired"]),
  withdrawn: Object.freeze([]),
  expired: Object.freeze([]),
} as const satisfies Readonly<
  Record<
    OpenPlatformComplianceConsentStatus,
    readonly OpenPlatformComplianceConsentStatus[]
  >
>);

export const OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TRANSITIONS = Object.freeze({
  submitted: Object.freeze(["verifyingIdentity", "cancelled"]),
  verifyingIdentity: Object.freeze(["verified", "rejected", "cancelled"]),
  verified: Object.freeze(["inProgress", "rejected"]),
  inProgress: Object.freeze(["fulfilled", "partiallyFulfilled", "rejected"]),
  partiallyFulfilled: Object.freeze(["fulfilled", "inProgress"]),
  fulfilled: Object.freeze([]),
  rejected: Object.freeze([]),
  cancelled: Object.freeze([]),
} as const satisfies Readonly<
  Record<
    OpenPlatformCompliancePrivacyRequestStatus,
    readonly OpenPlatformCompliancePrivacyRequestStatus[]
  >
>);

export const OPEN_PLATFORM_COMPLIANCE_RETENTION_POLICY_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["active", "retired"]),
  active: Object.freeze(["superseded", "retired"]),
  superseded: Object.freeze(["retired"]),
  retired: Object.freeze([]),
} as const satisfies Readonly<
  Record<
    OpenPlatformComplianceRetentionPolicyStatus,
    readonly OpenPlatformComplianceRetentionPolicyStatus[]
  >
>);

export const OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["assessing", "withdrawn"]),
  assessing: Object.freeze(["pendingApproval", "withdrawn"]),
  pendingApproval: Object.freeze(["approved", "rejected", "withdrawn"]),
  approved: Object.freeze(["expired", "withdrawn"]),
  rejected: Object.freeze([]),
  expired: Object.freeze([]),
  withdrawn: Object.freeze([]),
} as const satisfies Readonly<
  Record<
    OpenPlatformComplianceCrossBorderStatus,
    readonly OpenPlatformComplianceCrossBorderStatus[]
  >
>);

export const OPEN_PLATFORM_COMPLIANCE_VENDOR_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["pendingAssessment", "terminated"]),
  pendingAssessment: Object.freeze(["active", "terminated"]),
  active: Object.freeze(["suspended", "terminated"]),
  suspended: Object.freeze(["active", "terminated"]),
  terminated: Object.freeze([]),
} as const satisfies Readonly<
  Record<
    OpenPlatformComplianceVendorStatus,
    readonly OpenPlatformComplianceVendorStatus[]
  >
>);

export const OPEN_PLATFORM_COMPLIANCE_TRANSITIONS = Object.freeze({
  dataAsset: OPEN_PLATFORM_COMPLIANCE_DATA_ASSET_TRANSITIONS,
  consentRecord: OPEN_PLATFORM_COMPLIANCE_CONSENT_TRANSITIONS,
  privacyRequest: OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TRANSITIONS,
  retentionPolicy: OPEN_PLATFORM_COMPLIANCE_RETENTION_POLICY_TRANSITIONS,
  crossBorderAssessment: OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_TRANSITIONS,
  vendor: OPEN_PLATFORM_COMPLIANCE_VENDOR_TRANSITIONS,
} as const satisfies Readonly<
  Record<
    OpenPlatformComplianceStatefulEntityKind,
    Readonly<Record<string, readonly string[]>>
  >
>);

export function canTransitionOpenPlatformCompliance(
  entity: OpenPlatformComplianceStatefulEntityKind,
  from: string,
  to: string,
): boolean {
  const transitions = OPEN_PLATFORM_COMPLIANCE_TRANSITIONS[entity] as Readonly<
    Record<string, readonly string[]>
  >;
  return (transitions[from] ?? []).includes(to);
}

export function transitionOpenPlatformCompliance(
  entity: OpenPlatformComplianceStatefulEntityKind,
  from: string,
  to: string,
): string {
  if (!canTransitionOpenPlatformCompliance(entity, from, to)) {
    throw new OpenPlatformComplianceContractError(
      OPEN_PLATFORM_COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
      `${entity}.status`,
    );
  }
  return to;
}

export function isOpenPlatformComplianceTerminalStatus(
  entity: OpenPlatformComplianceStatefulEntityKind,
  status: string,
): boolean {
  const transitions = OPEN_PLATFORM_COMPLIANCE_TRANSITIONS[entity] as Readonly<
    Record<string, readonly string[]>
  >;
  return (transitions[status] ?? []).length === 0;
}

export const OPEN_PLATFORM_COMPLIANCE_REPORT_LIMITATIONS = Object.freeze([
  "The report records operator-declared status and evidence references only.",
  "No legal conclusion, adequacy determination, or regulatory filing status is asserted.",
  "Cross-border mechanisms and risk levels are recorded as declared and require legal review.",
  "Counts are scoped to records visible to the reporting tenant at generation time.",
] as const);
export type OpenPlatformComplianceReportLimitation =
  (typeof OPEN_PLATFORM_COMPLIANCE_REPORT_LIMITATIONS)[number];

export function normalizeOpenPlatformCompliancePageRequest(
  value: unknown = {},
): { readonly limit: number; readonly cursor?: string } {
  if (!isOpenPlatformComplianceRecord(value)) {
    throw new OpenPlatformComplianceContractError(
      OPEN_PLATFORM_COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
      "page",
    );
  }
  const rawLimit = value.limit;
  let limit: number = OPEN_PLATFORM_COMPLIANCE_DEFAULT_PAGE_SIZE;
  if (rawLimit !== undefined) {
    if (
      (typeof rawLimit !== "number" && typeof rawLimit !== "string") ||
      (typeof rawLimit === "number" && !Number.isSafeInteger(rawLimit)) ||
      (typeof rawLimit === "string" && !/^(?:0|[1-9][0-9]*)$/u.test(rawLimit))
    ) {
      throw new OpenPlatformComplianceContractError(
        OPEN_PLATFORM_COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
        "limit",
      );
    }
    const parsed = typeof rawLimit === "number" ? rawLimit : Number(rawLimit);
    if (
      !Number.isSafeInteger(parsed) ||
      parsed < 1 ||
      parsed > OPEN_PLATFORM_COMPLIANCE_MAX_PAGE_SIZE
    ) {
      throw new OpenPlatformComplianceContractError(
        OPEN_PLATFORM_COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
        "limit",
      );
    }
    limit = parsed;
  }
  const cursor = value.cursor;
  if (cursor !== undefined && (typeof cursor !== "string" || cursor.length < 1 || cursor.length > 512)) {
    throw new OpenPlatformComplianceContractError(
      OPEN_PLATFORM_COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
      "cursor",
    );
  }
  return cursor === undefined ? { limit } : { limit, cursor };
}

export function maskOpenPlatformComplianceSubjectRef(value: string): string {
  if (typeof value !== "string") return OPEN_PLATFORM_COMPLIANCE_REDACTED;
  const normalized = value.trim();
  if (normalized.length < 1) return OPEN_PLATFORM_COMPLIANCE_REDACTED;
  if (normalized.length <= 4) return "*".repeat(normalized.length);
  return `${"*".repeat(Math.min(12, normalized.length - 4))}${normalized.slice(-4)}`;
}

function sanitizeOpenPlatformComplianceErrorField(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) return undefined;
  return /^[A-Za-z0-9_.[\]-]+$/u.test(value) ? value : undefined;
}

function isOpenPlatformComplianceRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
