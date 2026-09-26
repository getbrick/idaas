import {
  OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_MECHANISMS,
  OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_DATA_ASSET_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_DATA_CATEGORIES,
  OPEN_PLATFORM_COMPLIANCE_DATA_CLASSIFICATIONS,
  OPEN_PLATFORM_COMPLIANCE_DATA_SUBJECT_GROUPS,
  OPEN_PLATFORM_COMPLIANCE_LEGAL_BASES,
  OPEN_PLATFORM_COMPLIANCE_VENDOR_STATUSES,
} from "@getbrick/idaas-contracts";
import type {
  OpenPlatformComplianceEvidenceReference,
  OpenPlatformComplianceReport,
  OpenPlatformComplianceReportGapCode,
} from "@getbrick/idaas-contracts";

export const COMPLIANCE_ENTITY_KINDS = Object.freeze([
  "dataAsset",
  "consentRecord",
  "privacyRequest",
  "retentionPolicy",
  "retentionExecution",
  "crossBorderAssessment",
  "vendor",
] as const);
export type ComplianceEntityKind = (typeof COMPLIANCE_ENTITY_KINDS)[number];

export const COMPLIANCE_ENTITY_PREFIXES = Object.freeze({
  dataAsset: "data-asset",
  consentRecord: "consent",
  privacyRequest: "privacy-request",
  retentionPolicy: "retention-policy",
  retentionExecution: "retention-execution",
  crossBorderAssessment: "cross-border",
  vendor: "vendor",
} satisfies Readonly<Record<ComplianceEntityKind, string>>);

export const COMPLIANCE_DATA_CLASSIFICATIONS =
  OPEN_PLATFORM_COMPLIANCE_DATA_CLASSIFICATIONS;
export type ComplianceDataClassification =
  (typeof COMPLIANCE_DATA_CLASSIFICATIONS)[number];

export const COMPLIANCE_DATA_CATEGORIES = OPEN_PLATFORM_COMPLIANCE_DATA_CATEGORIES;
export type ComplianceDataCategory =
  (typeof COMPLIANCE_DATA_CATEGORIES)[number];

export const COMPLIANCE_SENSITIVE_DATA_CATEGORIES = Object.freeze([
  "biometric",
  "financial",
  "health",
] as const);
export type ComplianceSensitiveDataCategory =
  (typeof COMPLIANCE_SENSITIVE_DATA_CATEGORIES)[number];

export const COMPLIANCE_LEGAL_BASES = OPEN_PLATFORM_COMPLIANCE_LEGAL_BASES;
export type ComplianceLegalBasis = (typeof COMPLIANCE_LEGAL_BASES)[number];

export const COMPLIANCE_DATA_SUBJECT_GROUPS =
  OPEN_PLATFORM_COMPLIANCE_DATA_SUBJECT_GROUPS;
export type ComplianceDataSubjectGroup =
  (typeof COMPLIANCE_DATA_SUBJECT_GROUPS)[number];

export const COMPLIANCE_DATA_ASSET_STATUSES =
  OPEN_PLATFORM_COMPLIANCE_DATA_ASSET_STATUSES;
export type ComplianceDataAssetStatus =
  (typeof COMPLIANCE_DATA_ASSET_STATUSES)[number];

export const COMPLIANCE_CONSENT_STATUSES = Object.freeze([
  "pending",
  "granted",
  "withdrawn",
  "expired",
] as const);
export type ComplianceConsentStatus =
  (typeof COMPLIANCE_CONSENT_STATUSES)[number];

export const COMPLIANCE_CONSENT_CHANNELS = Object.freeze([
  "web",
  "app",
  "api",
  "offline",
  "import",
] as const);
export type ComplianceConsentChannel =
  (typeof COMPLIANCE_CONSENT_CHANNELS)[number];

export const COMPLIANCE_PRIVACY_REQUEST_TYPES = Object.freeze([
  "access",
  "deletion",
  "correction",
  "revocation",
  "portability",
] as const);
export type CompliancePrivacyRequestType =
  (typeof COMPLIANCE_PRIVACY_REQUEST_TYPES)[number];

export const COMPLIANCE_PRIVACY_REQUEST_STATUSES = Object.freeze([
  "submitted",
  "verifyingIdentity",
  "verified",
  "inProgress",
  "fulfilled",
  "partiallyFulfilled",
  "rejected",
  "cancelled",
] as const);
export type CompliancePrivacyRequestStatus =
  (typeof COMPLIANCE_PRIVACY_REQUEST_STATUSES)[number];

export const COMPLIANCE_PRIVACY_REQUEST_TERMINAL_STATUSES = Object.freeze([
  "fulfilled",
  "partiallyFulfilled",
  "rejected",
  "cancelled",
] as const);
export type CompliancePrivacyRequestTerminalStatus =
  (typeof COMPLIANCE_PRIVACY_REQUEST_TERMINAL_STATUSES)[number];

export const COMPLIANCE_IDENTITY_VERIFICATION_STATUSES = Object.freeze([
  "notStarted",
  "pending",
  "verified",
  "failed",
] as const);
export type ComplianceIdentityVerificationStatus =
  (typeof COMPLIANCE_IDENTITY_VERIFICATION_STATUSES)[number];

export const COMPLIANCE_IDENTITY_VERIFICATION_METHODS = Object.freeze([
  "inSession",
  "reauthentication",
  "documentReview",
  "offlineManual",
  "trustedThirdParty",
] as const);
export type ComplianceIdentityVerificationMethod =
  (typeof COMPLIANCE_IDENTITY_VERIFICATION_METHODS)[number];

export const COMPLIANCE_PRIVACY_REQUEST_DECISIONS = Object.freeze([
  "granted",
  "partiallyGranted",
  "denied",
] as const);
export type CompliancePrivacyRequestDecision =
  (typeof COMPLIANCE_PRIVACY_REQUEST_DECISIONS)[number];

export const COMPLIANCE_PRIVACY_REQUEST_ACTIONS = Object.freeze([
  "exported",
  "erased",
  "corrected",
  "revoked",
] as const);
export type CompliancePrivacyRequestAction =
  (typeof COMPLIANCE_PRIVACY_REQUEST_ACTIONS)[number];

export const COMPLIANCE_SLA_STATES = Object.freeze([
  "withinSla",
  "dueSoon",
  "breached",
  "closedMet",
  "closedBreached",
] as const);
export type ComplianceSlaState = (typeof COMPLIANCE_SLA_STATES)[number];

export const COMPLIANCE_RETENTION_POLICY_STATUSES = Object.freeze([
  "draft",
  "active",
  "superseded",
  "retired",
] as const);
export type ComplianceRetentionPolicyStatus =
  (typeof COMPLIANCE_RETENTION_POLICY_STATUSES)[number];

export const COMPLIANCE_RETENTION_TRIGGERS = Object.freeze([
  "time",
  "event",
  "manual",
] as const);
export type ComplianceRetentionTrigger =
  (typeof COMPLIANCE_RETENTION_TRIGGERS)[number];

export const COMPLIANCE_RETENTION_ACTIONS = Object.freeze([
  "delete",
  "anonymize",
  "archive",
  "review",
] as const);
export type ComplianceRetentionAction =
  (typeof COMPLIANCE_RETENTION_ACTIONS)[number];

export const COMPLIANCE_RETENTION_EXECUTION_STATUSES = Object.freeze([
  "planned",
  "running",
  "completed",
  "failed",
  "skipped",
  "blocked",
] as const);
export type ComplianceRetentionExecutionStatus =
  (typeof COMPLIANCE_RETENTION_EXECUTION_STATUSES)[number];

export const COMPLIANCE_CROSS_BORDER_STATUSES =
  OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_STATUSES;
export type ComplianceCrossBorderStatus =
  (typeof COMPLIANCE_CROSS_BORDER_STATUSES)[number];

export const COMPLIANCE_RISK_LEVELS = Object.freeze([
  "low",
  "medium",
  "high",
  "critical",
] as const);
export type ComplianceRiskLevel = (typeof COMPLIANCE_RISK_LEVELS)[number];

export const COMPLIANCE_CROSS_BORDER_MECHANISMS =
  OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_MECHANISMS;
export type ComplianceCrossBorderMechanism =
  (typeof COMPLIANCE_CROSS_BORDER_MECHANISMS)[number];

export const COMPLIANCE_VENDOR_ROLES = Object.freeze([
  "processor",
  "subProcessor",
] as const);
export type ComplianceVendorRole = (typeof COMPLIANCE_VENDOR_ROLES)[number];

export const COMPLIANCE_VENDOR_STATUSES =
  OPEN_PLATFORM_COMPLIANCE_VENDOR_STATUSES;
export type ComplianceVendorStatus =
  (typeof COMPLIANCE_VENDOR_STATUSES)[number];

export const COMPLIANCE_ASSESSMENT_STATUSES = Object.freeze([
  "notStarted",
  "inProgress",
  "passed",
  "failed",
  "expired",
] as const);
export type ComplianceAssessmentStatus =
  (typeof COMPLIANCE_ASSESSMENT_STATUSES)[number];

export const COMPLIANCE_EVIDENCE_KINDS = Object.freeze([
  "document",
  "systemRecord",
  "ticket",
  "attestation",
] as const);
export type ComplianceEvidenceKind =
  (typeof COMPLIANCE_EVIDENCE_KINDS)[number];

export const COMPLIANCE_REDACTED = "[redacted]" as const;

export const COMPLIANCE_DEFAULT_PAGE_SIZE = 20;
export const COMPLIANCE_MAX_PAGE_SIZE = 100;
export const COMPLIANCE_SLA_DUE_SOON_DAYS = 3;
export const COMPLIANCE_DEFAULT_SLA_POLICY_CODE = "tenant-configured-baseline";
export const COMPLIANCE_MIN_RETENTION_DAYS = 1;
export const COMPLIANCE_MAX_RETENTION_DAYS = 36_500;
export const COMPLIANCE_MAX_RESPONSE_DAYS = 365;
export const COMPLIANCE_MAX_EVIDENCE_REFS = 64;
export const COMPLIANCE_MAX_AUDIT_METADATA_KEYS = 64;

export const COMPLIANCE_REPORT_GAP_CODES = Object.freeze({
  DATA_ASSET_WITHOUT_PURPOSE: "dataAssetWithoutPurpose",
  DATA_ASSET_WITHOUT_RETENTION_POLICY: "dataAssetWithoutRetentionPolicy",
  SENSITIVE_DATA_ASSET_WITHOUT_LEGAL_BASIS:
    "sensitiveDataAssetWithoutLegalBasis",
  CONSENT_WITHDRAWN_WHILE_ASSET_ACTIVE: "consentWithdrawnWhileAssetActive",
  PRIVACY_REQUEST_WITHOUT_IDENTITY_VERIFICATION:
    "privacyRequestWithoutIdentityVerification",
  PRIVACY_REQUEST_SLA_BREACHED: "privacyRequestSlaBreached",
  RETENTION_EXECUTION_FAILED: "retentionExecutionFailed",
  CROSS_BORDER_WITHOUT_MECHANISM: "crossBorderWithoutMechanism",
  CROSS_BORDER_AWAITING_DECISION: "crossBorderAwaitingDecision",
  VENDOR_ASSESSMENT_INCOMPLETE: "vendorAssessmentIncomplete",
  SUB_PROCESSOR_WITHOUT_PARENT: "subProcessorWithoutParent",
} as const satisfies Readonly<Record<string, OpenPlatformComplianceReportGapCode>>);

export type ComplianceReportGapCode =
  (typeof COMPLIANCE_REPORT_GAP_CODES)[keyof typeof COMPLIANCE_REPORT_GAP_CODES];

export const COMPLIANCE_REPORT_LIMITATIONS = Object.freeze([
  "The report records operator-declared status and evidence references only.",
  "No legal conclusion, adequacy determination, or regulatory filing status is asserted.",
  "Cross-border mechanisms and risk levels are recorded as declared and require legal review.",
  "Counts are scoped to records visible to the reporting tenant at generation time.",
] as const);

export interface ComplianceTenantRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: ComplianceEntityKind;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type ComplianceEvidence = OpenPlatformComplianceEvidenceReference;

export interface ComplianceDataAsset extends ComplianceTenantRecord {
  readonly kind: "dataAsset";
  readonly name: string;
  readonly code: string;
  readonly status: ComplianceDataAssetStatus;
  readonly classification: ComplianceDataClassification;
  readonly categories: readonly ComplianceDataCategory[];
  readonly personalData: boolean;
  readonly sensitivePersonalData: boolean;
  readonly legalBasis?: ComplianceLegalBasis;
  readonly purposes: readonly string[];
  readonly dataSubjects: readonly ComplianceDataSubjectGroup[];
  readonly residencyRegions: readonly string[];
  readonly processorVendorId?: string;
  readonly retentionPolicyId?: string;
  readonly retentionDays?: number;
  readonly crossBorder: boolean;
  readonly evidence: readonly ComplianceEvidence[];
}

export interface ComplianceConsentRecord extends ComplianceTenantRecord {
  readonly kind: "consentRecord";
  readonly status: ComplianceConsentStatus;
  readonly subjectRef: string;
  readonly subjectCount: number;
  readonly purpose: string;
  readonly legalBasis: "consent";
  readonly policyVersion: string;
  readonly channel: ComplianceConsentChannel;
  readonly language?: string;
  readonly scopes: readonly string[];
  readonly dataAssetIds: readonly string[];
  readonly grantedAt?: string;
  readonly withdrawnAt?: string;
  readonly expiresAt?: string;
  readonly withdrawalReason?: string;
  readonly proof: readonly ComplianceEvidence[];
}

export interface ComplianceIdentityVerification {
  readonly status: ComplianceIdentityVerificationStatus;
  readonly method?: ComplianceIdentityVerificationMethod;
  readonly attempts: number;
  readonly verifiedAt?: string;
  readonly verifiedByRef?: string;
  readonly evidence: readonly ComplianceEvidence[];
}

export interface CompliancePrivacyRequestSla {
  readonly policyCode: string;
  readonly responseDays: number;
  readonly dueAt: string;
  readonly respondedAt?: string;
  readonly closedAt?: string;
  readonly state: ComplianceSlaState;
}

export interface CompliancePrivacyRequestDecisionRecord {
  readonly decision: CompliancePrivacyRequestDecision;
  readonly decidedAt: string;
  readonly decidedByRef: string;
  readonly rationale?: string;
  readonly evidence: readonly ComplianceEvidence[];
}

export interface CompliancePrivacyRequestActionRecord {
  readonly action: CompliancePrivacyRequestAction;
  readonly dataAssetId: string;
  readonly executedAt: string;
  readonly affectedRecords?: number;
  readonly executionRef?: string;
}

export interface CompliancePrivacyRequest extends ComplianceTenantRecord {
  readonly kind: "privacyRequest";
  readonly requestType: CompliancePrivacyRequestType;
  readonly status: CompliancePrivacyRequestStatus;
  readonly statusReason?: string;
  readonly subjectRef: string;
  readonly subjectCount: number;
  readonly dataAssetIds: readonly string[];
  readonly identityVerification: ComplianceIdentityVerification;
  readonly sla: CompliancePrivacyRequestSla;
  readonly decision?: CompliancePrivacyRequestDecisionRecord;
  readonly actions: readonly CompliancePrivacyRequestActionRecord[];
  readonly duplicateOfId?: string;
}

export interface ComplianceRetentionPolicy extends ComplianceTenantRecord {
  readonly kind: "retentionPolicy";
  readonly name: string;
  readonly code: string;
  readonly status: ComplianceRetentionPolicyStatus;
  readonly trigger: ComplianceRetentionTrigger;
  readonly action: ComplianceRetentionAction;
  readonly retentionDays: number;
  readonly requiresApproval: boolean;
  readonly legalHold: boolean;
  readonly dataAssetIds: readonly string[];
  readonly residencyRegions: readonly string[];
  readonly lastExecutionId?: string;
  readonly evidence: readonly ComplianceEvidence[];
}

export interface ComplianceRetentionExecutionResult {
  readonly recordsScanned: number;
  readonly recordsDeleted: number;
  readonly recordsAnonymized: number;
  readonly recordsArchived: number;
  readonly completedAt?: string;
  readonly failureReason?: string;
  readonly evidence: readonly ComplianceEvidence[];
}

export interface ComplianceRetentionExecution extends ComplianceTenantRecord {
  readonly kind: "retentionExecution";
  readonly version: 1;
  readonly policyId: string;
  readonly dataAssetIds: readonly string[];
  readonly status: ComplianceRetentionExecutionStatus;
  readonly action: ComplianceRetentionAction;
  readonly runId: string;
  readonly blockedReason?: string;
  readonly result: ComplianceRetentionExecutionResult;
  readonly recordedByRef: string;
  readonly occurredAt: string;
}

export interface ComplianceCrossBorderAssessment
  extends ComplianceTenantRecord {
  readonly kind: "crossBorderAssessment";
  readonly title: string;
  readonly code: string;
  readonly status: ComplianceCrossBorderStatus;
  readonly sourceRegion: string;
  readonly destinationRegions: readonly string[];
  readonly transferPurpose: string;
  readonly dataAssetIds: readonly string[];
  readonly personalData: boolean;
  readonly sensitivePersonalData: boolean;
  readonly riskLevel: ComplianceRiskLevel;
  readonly riskFactors: readonly string[];
  readonly mechanisms: readonly ComplianceCrossBorderMechanism[];
  readonly recipientVendorId?: string;
  readonly decidedAt?: string;
  readonly decidedByRef?: string;
  readonly validUntil?: string;
  readonly evidence: readonly ComplianceEvidence[];
}

export interface ComplianceVendorAssessment {
  readonly status: ComplianceAssessmentStatus;
  readonly assessedAt?: string;
  readonly assessedByRef?: string;
  readonly evidence: readonly ComplianceEvidence[];
}

export interface ComplianceVendor extends ComplianceTenantRecord {
  readonly kind: "vendor";
  readonly role: ComplianceVendorRole;
  readonly status: ComplianceVendorStatus;
  readonly code: string;
  readonly legalName: string;
  readonly displayName?: string;
  readonly regions: readonly string[];
  readonly dataAssetIds: readonly string[];
  readonly dataCategories: readonly ComplianceDataCategory[];
  readonly parentVendorId?: string;
  readonly crossBorder: boolean;
  readonly contractEffectiveAt?: string;
  readonly contractTerminatedAt?: string;
  readonly assessment: ComplianceVendorAssessment;
  readonly evidence: readonly ComplianceEvidence[];
}

export type ComplianceRecord =
  | ComplianceDataAsset
  | ComplianceConsentRecord
  | CompliancePrivacyRequest
  | ComplianceRetentionPolicy
  | ComplianceRetentionExecution
  | ComplianceCrossBorderAssessment
  | ComplianceVendor;

export type ComplianceStatefulRecord =
  | ComplianceDataAsset
  | ComplianceConsentRecord
  | CompliancePrivacyRequest
  | ComplianceRetentionPolicy
  | ComplianceCrossBorderAssessment
  | ComplianceVendor;

export type ComplianceAppendOnlyRecord = ComplianceRetentionExecution;

export type ComplianceReport = OpenPlatformComplianceReport;

export interface ComplianceDependencyReadiness {
  readonly storage: "memory" | "database" | "persistent";
  readonly distributed: boolean;
  readonly ready: () => boolean;
}
