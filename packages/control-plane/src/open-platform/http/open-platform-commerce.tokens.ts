import type { CommerceDomainService } from "../commerce/service.js";
import type { CommerceAuditPort } from "../commerce/audit.js";
import type { CommerceAuthorizationPort } from "../commerce/authorization.js";
import type { CommerceIdempotencyPort } from "../commerce/idempotency.js";

export const OPEN_PLATFORM_COMMERCE_SERVICE =
  "OPEN_PLATFORM_COMMERCE_SERVICE";
export const OPEN_PLATFORM_COMMERCE_MODE = "OPEN_PLATFORM_COMMERCE_MODE";
export const OPEN_PLATFORM_COMMERCE_SERVICE_TOKEN = OPEN_PLATFORM_COMMERCE_SERVICE;
export const OPEN_PLATFORM_COMMERCE_DOMAIN_SERVICE = OPEN_PLATFORM_COMMERCE_SERVICE;
export const OPEN_PLATFORM_COMMERCE_AUTHORIZATION =
  "OPEN_PLATFORM_COMMERCE_AUTHORIZATION";
export const OPEN_PLATFORM_COMMERCE_AUTHORIZATION_PORT =
  OPEN_PLATFORM_COMMERCE_AUTHORIZATION;
export const OPEN_PLATFORM_COMMERCE_AUDIT = "OPEN_PLATFORM_COMMERCE_AUDIT";
export const OPEN_PLATFORM_COMMERCE_AUDIT_PORT = OPEN_PLATFORM_COMMERCE_AUDIT;
export const OPEN_PLATFORM_COMMERCE_IDEMPOTENCY =
  "OPEN_PLATFORM_COMMERCE_IDEMPOTENCY";
export const OPEN_PLATFORM_COMMERCE_IDEMPOTENCY_PORT =
  OPEN_PLATFORM_COMMERCE_IDEMPOTENCY;
export const OPEN_PLATFORM_COMMERCE_SECURITY =
  "OPEN_PLATFORM_COMMERCE_SECURITY";

export type OpenPlatformCommerceService = CommerceDomainService;
export type { CommerceAuditPort, CommerceAuthorizationPort, CommerceIdempotencyPort };
