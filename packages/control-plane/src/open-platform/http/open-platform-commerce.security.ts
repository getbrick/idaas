import { Inject, Injectable } from "@nestjs/common";
import {
  isCommerceAuthorizationProductionReady,
  isCommerceAuthorizationPort,
  requireCommerceAuthorization,
  type CommerceAuthorizationAction,
  type CommerceAuthorizationPort,
  type CommerceAuthorizationResource,
} from "../commerce/authorization.js";
import {
  COMMERCE_AUDIT_SOURCE,
  sanitizeCommerceAuditMetadata,
  type CommerceAuditOutcome,
  type CommerceAuditPort,
  type CommerceAuditResourceType,
} from "../commerce/audit.js";
import {
  commerceStorageUnavailable,
  isOpenPlatformCommerceError,
} from "../commerce/errors.js";
import type { CommerceDependencyReadiness } from "../commerce/types.js";
import type { OpenPlatformRequestContext } from "../authorization.js";
import {
  OPEN_PLATFORM_COMMERCE_AUTHORIZATION,
  OPEN_PLATFORM_COMMERCE_AUDIT,
  OPEN_PLATFORM_COMMERCE_MODE,
} from "./open-platform-commerce.tokens.js";

export const COMMERCE_AUDIT_METADATA_FIELDS = Object.freeze([
  "operation",
  "previousStatus",
  "replayed",
  "resourceKind",
  "status",
  "targetStatus",
  "outcome",
  "fromStatus",
  "toStatus",
  "invoiceId",
  "disputeId",
  "noteLength",
] as const);

export type CommerceAuditMetadataField =
  (typeof COMMERCE_AUDIT_METADATA_FIELDS)[number];

export interface CommerceSecurityAccess {
  readonly action: CommerceAuthorizationAction;
  readonly resource: CommerceAuthorizationResource;
  readonly resourceId?: string;
}

export interface CommerceSecurityWrite extends CommerceSecurityAccess {
  readonly action:
    | "create"
    | "update"
    | "record"
    | "dispute.review"
    | "dispute.decide"
    | "dispute.withdraw";
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface CommerceSecurityReadiness {
  readonly ready: boolean;
  readonly authorizationReady: boolean;
  readonly auditReady: boolean;
}

@Injectable()
export class OpenPlatformCommerceSecurity {
  readonly mode: "development" | "test" | "production";
  private readonly authorization: CommerceAuthorizationPort;
  private readonly audit: CommerceAuditPort;

  constructor(
    @Inject(OPEN_PLATFORM_COMMERCE_AUTHORIZATION)
    authorization: CommerceAuthorizationPort,
    @Inject(OPEN_PLATFORM_COMMERCE_AUDIT)
    audit: CommerceAuditPort,
    @Inject(OPEN_PLATFORM_COMMERCE_MODE)
    mode: "development" | "test" | "production",
  ) {
    if (!isCommerceAuthorizationPort(authorization)) {
      throw new Error("[getbrick-idaas] open platform commerce authorization is invalid");
    }
    if (audit === null || typeof audit !== "object" || typeof audit.append !== "function") {
      throw new Error("[getbrick-idaas] open platform commerce audit port is invalid");
    }
    if (mode !== "development" && mode !== "test" && mode !== "production") {
      throw new Error("[getbrick-idaas] open platform commerce mode is invalid");
    }
    this.authorization = authorization;
    this.audit = audit;
    this.mode = mode;
  }

  async authorize(
    context: OpenPlatformRequestContext,
    access: CommerceSecurityAccess,
  ): Promise<OpenPlatformRequestContext> {
    try {
      return await requireCommerceAuthorization(this.authorization, {
        context,
        tenantId: context.tenantId,
        action: access.action,
        resource: access.resource,
        ...(access.resourceId === undefined ? {} : { resourceId: access.resourceId }),
      });
    } catch (error) {
      if (access.action !== "read") {
        await this.append(context, access, "denied", false);
      }
      throw error;
    }
  }

  async recordWrite(
    context: OpenPlatformRequestContext,
    write: CommerceSecurityWrite,
  ): Promise<void> {
    await this.append(context, write, "success", true);
  }

  async recordFailure(
    context: OpenPlatformRequestContext,
    write: CommerceSecurityWrite,
  ): Promise<void> {
    await this.append(context, write, "failure", false);
  }

  async isReady(): Promise<CommerceSecurityReadiness> {
    const authorizationReady = this.mode === "production"
      ? isCommerceAuthorizationProductionReady(this.authorization)
      : isCommerceAuthorizationPort(this.authorization);
    const auditReady = this.mode === "production"
      ? this.audit.productionReady === true &&
        this.audit.readiness !== undefined &&
        await safeCommerceAuditReady(this.audit.readiness)
      : this.audit.readiness === undefined || await safeCommerceAuditReady(this.audit.readiness);
    return {
      ready: authorizationReady && auditReady,
      authorizationReady,
      auditReady,
    };
  }

  private async append(
    context: OpenPlatformRequestContext,
    access: CommerceSecurityAccess & {
      readonly metadata?: Readonly<Record<string, unknown>>;
    },
    outcome: CommerceAuditOutcome,
    failClosed: boolean,
  ): Promise<void> {
    try {
      await this.audit.append({
        tenantId: context.tenantId,
        action: `${access.resource}.${access.action}`,
        outcome,
        actor: { type: "user", id: context.actorId },
        target: {
          type: access.resource satisfies CommerceAuditResourceType,
          id: access.resourceId ?? "unknown",
        },
        requestId: context.requestId,
        metadata: sanitizeCommerceAuditMetadata(
          allowlistedCommerceAuditMetadata(access.metadata),
        ),
        source: COMMERCE_AUDIT_SOURCE,
      });
    } catch (error) {
      if (isOpenPlatformCommerceError(error)) throw error;
      if (failClosed && this.mode === "production") {
        throw commerceStorageUnavailable();
      }
    }
  }
}

export function allowlistedCommerceAuditMetadata(
  value: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, unknown>> {
  if (value === undefined) return {};
  const output: Record<string, unknown> = {};
  for (const field of COMMERCE_AUDIT_METADATA_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) continue;
    output[field] = value[field];
  }
  return output;
}

async function safeCommerceAuditReady(
  readiness: CommerceDependencyReadiness | undefined,
): Promise<boolean> {
  if (readiness === undefined || typeof readiness.ready !== "function") return false;
  try {
    return (await readiness.ready()) === true;
  } catch {
    return false;
  }
}
