import type { ComplianceDomainService } from "../compliance/service.js";
import type { ComplianceAuditPort } from "../compliance/events.js";
import type { ComplianceAuthorizationPort } from "../compliance/authorization.js";
import type { ComplianceIdempotencyPort } from "../compliance/idempotency.js";

export const OPEN_PLATFORM_COMPLIANCE_SERVICE = "OPEN_PLATFORM_COMPLIANCE_SERVICE";
export const OPEN_PLATFORM_COMPLIANCE_MODE = "OPEN_PLATFORM_COMPLIANCE_MODE";
export const OPEN_PLATFORM_COMPLIANCE_SERVICE_TOKEN = OPEN_PLATFORM_COMPLIANCE_SERVICE;
export const OPEN_PLATFORM_COMPLIANCE_DOMAIN_SERVICE = OPEN_PLATFORM_COMPLIANCE_SERVICE;
export const OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION =
  "OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION";
export const OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION_PORT =
  OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION;
export const OPEN_PLATFORM_COMPLIANCE_AUDIT = "OPEN_PLATFORM_COMPLIANCE_AUDIT";
export const OPEN_PLATFORM_COMPLIANCE_AUDIT_PORT = OPEN_PLATFORM_COMPLIANCE_AUDIT;
export const OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY =
  "OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY";
export const OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY_PORT =
  OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY;
export const OPEN_PLATFORM_COMPLIANCE_SECURITY = "OPEN_PLATFORM_COMPLIANCE_SECURITY";

export type OpenPlatformComplianceService = ComplianceDomainService;
export type {
  ComplianceAuditPort,
  ComplianceAuthorizationPort,
  ComplianceIdempotencyPort,
};
