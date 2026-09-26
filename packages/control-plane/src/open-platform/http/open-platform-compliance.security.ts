import { Inject, Injectable } from "@nestjs/common";
import {
  isComplianceAuthorizationPort,
  isComplianceAuthorizationProductionReady,
  requireComplianceAuthorization,
  type ComplianceAuthorizationAction,
  type ComplianceAuthorizationPort,
  type ComplianceAuthorizationResource,
} from "../compliance/authorization.js";
import {
  COMPLIANCE_AUDIT_SOURCE,
  type ComplianceAuditOutcome,
  type ComplianceAuditPort,
  type ComplianceAuditResourceType,
} from "../compliance/events.js";
import {
  isOpenPlatformComplianceError,
  complianceStorageUnavailable,
} from "../compliance/errors.js";
import { toComplianceAuditMetadata } from "../compliance/redaction.js";
import type { ComplianceDependencyReadiness } from "../compliance/types.js";
import type { OpenPlatformRequestContext } from "../authorization.js";
import {
  OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION,
  OPEN_PLATFORM_COMPLIANCE_AUDIT,
  OPEN_PLATFORM_COMPLIANCE_MODE,
} from "./open-platform-compliance.tokens.js";

export const COMPLIANCE_AUDIT_METADATA_FIELDS = Object.freeze([
  "operation",
  "previousStatus",
  "replayed",
  "resourceKind",
  "status",
  "targetStatus",
] as const);

export type ComplianceAuditMetadataField =
  (typeof COMPLIANCE_AUDIT_METADATA_FIELDS)[number];

export interface ComplianceSecurityAccess {
  readonly action: ComplianceAuthorizationAction;
  readonly resource: ComplianceAuthorizationResource;
  readonly resourceId?: string;
}

export interface ComplianceSecurityWrite extends ComplianceSecurityAccess {
  readonly action: "create" | "update" | "record" | "approve";
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ComplianceSecurityReadiness {
  readonly ready: boolean;
  readonly authorizationReady: boolean;
  readonly auditReady: boolean;
}

@Injectable()
export class OpenPlatformComplianceSecurity {
  readonly mode: "development" | "test" | "production";
  private readonly authorization: ComplianceAuthorizationPort;
  private readonly audit: ComplianceAuditPort;

  constructor(
    @Inject(OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION)
    authorization: ComplianceAuthorizationPort,
    @Inject(OPEN_PLATFORM_COMPLIANCE_AUDIT)
    audit: ComplianceAuditPort,
    @Inject(OPEN_PLATFORM_COMPLIANCE_MODE)
    mode: "development" | "test" | "production",
  ) {
    if (!isComplianceAuthorizationPort(authorization)) {
      throw new Error("[getbrick-idaas] open platform compliance authorization is invalid");
    }
    if (audit === null || typeof audit !== "object" || typeof audit.append !== "function") {
      throw new Error("[getbrick-idaas] open platform compliance audit port is invalid");
    }
    if (mode !== "development" && mode !== "test" && mode !== "production") {
      throw new Error("[getbrick-idaas] open platform compliance mode is invalid");
    }
    this.authorization = authorization;
    this.audit = audit;
    this.mode = mode;
  }

  async authorize(
    context: OpenPlatformRequestContext,
    access: ComplianceSecurityAccess,
  ): Promise<OpenPlatformRequestContext> {
    try {
      return await requireComplianceAuthorization(this.authorization, {
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
    write: ComplianceSecurityWrite,
  ): Promise<void> {
    await this.append(context, write, "success", true);
  }

  async recordFailure(
    context: OpenPlatformRequestContext,
    write: ComplianceSecurityWrite,
  ): Promise<void> {
    await this.append(context, write, "failure", false);
  }

  async isReady(): Promise<ComplianceSecurityReadiness> {
    const authorizationReady = this.mode === "production"
      ? isComplianceAuthorizationProductionReady(this.authorization)
      : isComplianceAuthorizationPort(this.authorization);
    const auditReady = this.mode === "production"
      ? this.audit.productionReady === true &&
        this.audit.readiness !== undefined &&
        await safeComplianceAuditReady(this.audit.readiness)
      : this.audit.readiness === undefined ||
        await safeComplianceAuditReady(this.audit.readiness);
    return {
      ready: authorizationReady && auditReady,
      authorizationReady,
      auditReady,
    };
  }

  private async append(
    context: OpenPlatformRequestContext,
    access: ComplianceSecurityAccess & {
      readonly metadata?: Readonly<Record<string, unknown>>;
    },
    outcome: ComplianceAuditOutcome,
    failClosed: boolean,
  ): Promise<void> {
    try {
      await this.audit.append({
        tenantId: context.tenantId,
        action: `${access.resource}.${access.action}`,
        outcome,
        actor: { type: "user", id: context.actorId },
        target: {
          type: access.resource satisfies ComplianceAuditResourceType,
          id: access.resourceId ?? "unknown",
        },
        requestId: context.requestId,
        metadata: toComplianceAuditMetadata(
          allowlistedComplianceAuditMetadata(access.metadata),
        ),
        source: COMPLIANCE_AUDIT_SOURCE,
      });
    } catch (error) {
      if (isOpenPlatformComplianceError(error)) throw error;
      if (failClosed && this.mode === "production") {
        throw complianceStorageUnavailable();
      }
    }
  }
}

export function allowlistedComplianceAuditMetadata(
  value: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, unknown>> {
  if (value === undefined) return {};
  const output: Record<string, unknown> = {};
  for (const field of COMPLIANCE_AUDIT_METADATA_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) continue;
    output[field] = value[field];
  }
  return output;
}

async function safeComplianceAuditReady(
  readiness: ComplianceDependencyReadiness | undefined,
): Promise<boolean> {
  if (readiness === undefined || typeof readiness.ready !== "function") return false;
  try {
    return (await readiness.ready()) === true;
  } catch {
    return false;
  }
}
