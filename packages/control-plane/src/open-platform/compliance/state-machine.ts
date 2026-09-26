import { OPEN_PLATFORM_COMPLIANCE_TRANSITIONS } from "@getbrick/idaas-contracts";
import { complianceInvalidStateTransition } from "./errors.js";
import type {
  ComplianceConsentStatus,
  ComplianceCrossBorderStatus,
  ComplianceDataAssetStatus,
  CompliancePrivacyRequestStatus,
  CompliancePrivacyRequestTerminalStatus,
  ComplianceRetentionPolicyStatus,
  ComplianceVendorStatus,
} from "./types.js";

export const COMPLIANCE_STATEFUL_ENTITY_KINDS = Object.freeze([
  "dataAsset",
  "consentRecord",
  "privacyRequest",
  "retentionPolicy",
  "crossBorderAssessment",
  "vendor",
] as const);

export type ComplianceStatefulEntityKind =
  (typeof COMPLIANCE_STATEFUL_ENTITY_KINDS)[number];

export const COMPLIANCE_TRANSITIONS = OPEN_PLATFORM_COMPLIANCE_TRANSITIONS;

export const COMPLIANCE_DATA_ASSET_TRANSITIONS =
  COMPLIANCE_TRANSITIONS.dataAsset;
export const COMPLIANCE_CONSENT_TRANSITIONS =
  COMPLIANCE_TRANSITIONS.consentRecord;
export const COMPLIANCE_PRIVACY_REQUEST_TRANSITIONS =
  COMPLIANCE_TRANSITIONS.privacyRequest;
export const COMPLIANCE_RETENTION_POLICY_TRANSITIONS =
  COMPLIANCE_TRANSITIONS.retentionPolicy;
export const COMPLIANCE_CROSS_BORDER_TRANSITIONS =
  COMPLIANCE_TRANSITIONS.crossBorderAssessment;
export const COMPLIANCE_VENDOR_TRANSITIONS = COMPLIANCE_TRANSITIONS.vendor;

export function complianceTransitionsFor(
  entity: ComplianceStatefulEntityKind,
): Readonly<Record<string, readonly string[]>> {
  return COMPLIANCE_TRANSITIONS[entity] as Readonly<
    Record<string, readonly string[]>
  >;
}

export function complianceAllowedTargets(
  entity: ComplianceStatefulEntityKind,
  status: string,
): readonly string[] {
  return complianceTransitionsFor(entity)[status] ?? [];
}

export function isComplianceTerminalStatus(
  entity: ComplianceStatefulEntityKind,
  status: string,
): boolean {
  return complianceAllowedTargets(entity, status).length === 0;
}

export function canTransitionDataAsset(
  from: ComplianceDataAssetStatus,
  to: ComplianceDataAssetStatus,
): boolean {
  const targets = COMPLIANCE_DATA_ASSET_TRANSITIONS[from] as readonly ComplianceDataAssetStatus[];
  return targets.includes(to);
}

export function canTransitionConsent(
  from: ComplianceConsentStatus,
  to: ComplianceConsentStatus,
): boolean {
  const targets = COMPLIANCE_CONSENT_TRANSITIONS[from] as readonly ComplianceConsentStatus[];
  return targets.includes(to);
}

export function canTransitionPrivacyRequest(
  from: CompliancePrivacyRequestStatus,
  to: CompliancePrivacyRequestStatus,
): boolean {
  const targets = COMPLIANCE_PRIVACY_REQUEST_TRANSITIONS[from] as readonly CompliancePrivacyRequestStatus[];
  return targets.includes(to);
}

export function canTransitionRetentionPolicy(
  from: ComplianceRetentionPolicyStatus,
  to: ComplianceRetentionPolicyStatus,
): boolean {
  const targets = COMPLIANCE_RETENTION_POLICY_TRANSITIONS[from] as readonly ComplianceRetentionPolicyStatus[];
  return targets.includes(to);
}

export function canTransitionCrossBorder(
  from: ComplianceCrossBorderStatus,
  to: ComplianceCrossBorderStatus,
): boolean {
  const targets = COMPLIANCE_CROSS_BORDER_TRANSITIONS[from] as readonly ComplianceCrossBorderStatus[];
  return targets.includes(to);
}

export function canTransitionVendor(
  from: ComplianceVendorStatus,
  to: ComplianceVendorStatus,
): boolean {
  const targets = COMPLIANCE_VENDOR_TRANSITIONS[from] as readonly ComplianceVendorStatus[];
  return targets.includes(to);
}

export function assertDataAssetTransition(
  from: ComplianceDataAssetStatus,
  to: ComplianceDataAssetStatus,
): void {
  assertComplianceTransition(
    "dataAsset",
    from,
    to,
    canTransitionDataAsset(from, to),
  );
}

export function assertConsentTransition(
  from: ComplianceConsentStatus,
  to: ComplianceConsentStatus,
): void {
  assertComplianceTransition(
    "consentRecord",
    from,
    to,
    canTransitionConsent(from, to),
  );
}

export function assertPrivacyRequestTransition(
  from: CompliancePrivacyRequestStatus,
  to: CompliancePrivacyRequestStatus,
): void {
  assertComplianceTransition(
    "privacyRequest",
    from,
    to,
    canTransitionPrivacyRequest(from, to),
  );
}

export function assertRetentionPolicyTransition(
  from: ComplianceRetentionPolicyStatus,
  to: ComplianceRetentionPolicyStatus,
): void {
  assertComplianceTransition(
    "retentionPolicy",
    from,
    to,
    canTransitionRetentionPolicy(from, to),
  );
}

export function assertCrossBorderTransition(
  from: ComplianceCrossBorderStatus,
  to: ComplianceCrossBorderStatus,
): void {
  assertComplianceTransition(
    "crossBorderAssessment",
    from,
    to,
    canTransitionCrossBorder(from, to),
  );
}

export function assertVendorTransition(
  from: ComplianceVendorStatus,
  to: ComplianceVendorStatus,
): void {
  assertComplianceTransition("vendor", from, to, canTransitionVendor(from, to));
}

export function isPrivacyRequestTerminalStatus(
  status: CompliancePrivacyRequestStatus,
): status is CompliancePrivacyRequestTerminalStatus {
  return (
    status === "fulfilled" ||
    status === "partiallyFulfilled" ||
    status === "rejected" ||
    status === "cancelled"
  );
}

export function privacyRequestRequiresIdentityVerification(
  target: CompliancePrivacyRequestStatus,
): boolean {
  return (
    target === "inProgress" ||
    target === "fulfilled" ||
    target === "partiallyFulfilled"
  );
}

export function privacyRequestRequiresDecision(
  target: CompliancePrivacyRequestStatus,
): boolean {
  return (
    target === "fulfilled" ||
    target === "partiallyFulfilled" ||
    target === "rejected"
  );
}

function assertComplianceTransition(
  entity: ComplianceStatefulEntityKind,
  from: string,
  to: string,
  allowed: boolean,
): void {
  if (!allowed) throw complianceInvalidStateTransition(entity, from, to);
}
