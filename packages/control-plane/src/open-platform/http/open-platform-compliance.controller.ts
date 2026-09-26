import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  Inject,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
  UseFilters,
  UseGuards,
  UseInterceptors,
} from "@nestjs/common";
import {
  authenticationRequired,
  tenantMismatch,
} from "../errors.js";
import {
  isOpenPlatformRequestContext,
  type OpenPlatformRequestContext,
} from "../authorization.js";
import {
  complianceResourceNotFound,
  complianceValidationError,
} from "../compliance/errors.js";
import { normalizeComplianceIdempotencyKey } from "../compliance/idempotency.js";
import {
  toComplianceConsentRecordView,
  toComplianceCrossBorderAssessmentView,
  toComplianceDataAssetView,
  toCompliancePageView,
  toCompliancePrivacyRequestSlaView,
  toCompliancePrivacyRequestView,
  toComplianceReportView,
  toComplianceRetentionExecutionView,
  toComplianceRetentionPolicyView,
  toComplianceVendorView,
} from "../compliance/view.js";
import { COMPLIANCE_MAX_PAGE_SIZE } from "../compliance/types.js";
import type {
  ComplianceConsentRecord,
  ComplianceCrossBorderAssessment,
  ComplianceDataAsset,
  CompliancePrivacyRequest,
  ComplianceRetentionExecution,
  ComplianceRetentionPolicy,
  ComplianceVendor,
} from "../compliance/types.js";
import type {
  ComplianceCrossBorderAssessmentView,
  ComplianceDataAssetView,
  CompliancePrivacyRequestView,
  ComplianceRetentionPolicyView,
  ComplianceVendorView,
} from "../compliance/view.js";
import type {
  CreateConsentRecordCommand,
  CreateCrossBorderAssessmentCommand,
  CreateDataAssetCommand,
  CreatePrivacyRequestCommand,
  CreateRetentionPolicyCommand,
  CreateVendorCommand,
  DecidePrivacyRequestCommand,
  ExpireConsentCommand,
  GrantConsentCommand,
  RecordIdentityVerificationCommand,
  RecordPrivacyRequestActionCommand,
  RecordRetentionExecutionCommand,
  RecordVendorAssessmentCommand,
  TransitionCrossBorderCommand,
  TransitionDataAssetCommand,
  TransitionPrivacyRequestCommand,
  TransitionRetentionPolicyCommand,
  TransitionVendorCommand,
  UpdateDataAssetCommand,
  WithdrawConsentCommand,
} from "../compliance/service.js";
import { OpenPlatformHttpContextGuard } from "./open-platform-http.guard.js";
import { OpenPlatformComplianceHttpExceptionFilter } from "./open-platform-compliance.filter.js";
import { OpenPlatformHttpResponseInterceptor } from "./open-platform-http.interceptor.js";
import {
  COMPLIANCE_IDEMPOTENCY_REPLAY_HEADER,
  OpenPlatformComplianceIdempotency,
} from "./open-platform-compliance.idempotency.js";
import { OpenPlatformComplianceSecurity } from "./open-platform-compliance.security.js";
import { OPEN_PLATFORM_COMPLIANCE_SERVICE } from "./open-platform-compliance.tokens.js";
import {
  OPEN_PLATFORM_HTTP_BASE_PATH,
  OPEN_PLATFORM_HTTP_CONTEXT,
  isOpenPlatformHttpRecord,
  type OpenPlatformHttpRequest,
} from "./open-platform-http.types.js";
import type { OpenPlatformComplianceService } from "./open-platform-compliance.tokens.js";

export const OPEN_PLATFORM_COMPLIANCE_BASE_PATH = `${OPEN_PLATFORM_HTTP_BASE_PATH}/compliance`;

const LIST_QUERY_KEYS = Object.freeze([
  "tenantId",
  "tenant_id",
  "status",
  "ids",
  "cursor",
  "limit",
  "pageSize",
] as const);

const REPORT_QUERY_KEYS = Object.freeze([
  "tenantId",
  "tenant_id",
  "from",
  "to",
  "generatedAt",
] as const);

const SLA_QUERY_KEYS = Object.freeze([
  "tenantId",
  "tenant_id",
  "at",
] as const);

const TENANT_QUERY_KEYS = Object.freeze(["tenantId", "tenant_id"] as const);

type ComplianceWriteResource =
  | "dataAsset"
  | "consentRecord"
  | "privacyRequest"
  | "retentionPolicy"
  | "retentionExecution"
  | "crossBorderAssessment"
  | "vendor"
  | "report";

type ComplianceStatusResource = Exclude<ComplianceWriteResource, "retentionExecution" | "report">;

interface ComplianceWriteAudit {
  readonly action: "create" | "update" | "record" | "approve";
  readonly resource: ComplianceWriteResource;
  readonly resourceId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

interface ComplianceWriteResponse {
  setHeader?(name: string, value: string): unknown;
}

@Controller(OPEN_PLATFORM_COMPLIANCE_BASE_PATH)
@UseGuards(OpenPlatformHttpContextGuard)
@UseFilters(OpenPlatformComplianceHttpExceptionFilter)
@UseInterceptors(OpenPlatformHttpResponseInterceptor)
export class OpenPlatformComplianceController {
  constructor(
    @Inject(OPEN_PLATFORM_COMPLIANCE_SERVICE)
    private readonly service: OpenPlatformComplianceService,
    @Inject(OpenPlatformComplianceSecurity)
    private readonly security: OpenPlatformComplianceSecurity,
    @Inject(OpenPlatformComplianceIdempotency)
    private readonly idempotency: OpenPlatformComplianceIdempotency,
  ) {}

  @Get("data-assets")
  async listDataAssets(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, LIST_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, { action: "read", resource: "dataAsset" });
    const page = await this.service.listDataAssets({
      ...this.listQuery(value),
      tenantId,
    });
    return toCompliancePageView(page, toComplianceDataAssetView);
  }

  @Get("data-assets/:dataAssetId")
  async getDataAsset(
    @Param("dataAssetId") dataAssetId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, TENANT_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "dataAsset",
      resourceId: dataAssetId,
    });
    const record = await this.service.getDataAsset(tenantId, dataAssetId);
    if (record === undefined) throw complianceResourceNotFound("dataAsset");
    return toComplianceDataAssetView(record);
  }

  @Post("data-assets")
  @HttpCode(201)
  async createDataAsset(
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: CreateDataAssetCommand = {
      tenantId,
      name: value.name as string,
      code: value.code as string,
      classification: value.classification as CreateDataAssetCommand["classification"],
      categories: value.categories as CreateDataAssetCommand["categories"],
      personalData: value.personalData as boolean,
      sensitivePersonalData: value.sensitivePersonalData as boolean,
      residencyRegions: value.residencyRegions as string[],
      crossBorder: value.crossBorder as boolean,
      ...this.optional(value, "legalBasis"),
      ...this.optional(value, "purposes"),
      ...this.optional(value, "dataSubjects"),
      ...this.optional(value, "processorVendorId"),
      ...this.optional(value, "retentionPolicyId"),
      ...this.optional(value, "retentionDays"),
      ...this.optional(value, "evidence"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "create",
        resource: "dataAsset",
        metadata: { status: "draft" },
      },
      idempotencyKey,
      operation: "dataAsset.create",
      request: command,
      toView: toComplianceDataAssetView,
      action: () => this.service.createDataAsset(command),
    });
  }

  @Patch("data-assets/:dataAssetId")
  async updateDataAsset(
    @Param("dataAssetId") dataAssetId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: UpdateDataAssetCommand = {
      tenantId,
      id: dataAssetId,
      ...this.optional(value, "name"),
      ...this.optional(value, "classification"),
      ...this.optional(value, "categories"),
      ...this.optionalNullable(value, "legalBasis"),
      ...this.optional(value, "purposes"),
      ...this.optional(value, "dataSubjects"),
      ...this.optional(value, "residencyRegions"),
      ...this.optionalNullable(value, "processorVendorId"),
      ...this.optionalNullable(value, "retentionPolicyId"),
      ...this.optionalNullable(value, "retentionDays"),
      ...this.optional(value, "crossBorder"),
      ...this.optional(value, "evidence"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "update",
        resource: "dataAsset",
        resourceId: dataAssetId,
      },
      idempotencyKey,
      operation: "dataAsset.update",
      request: command,
      toView: toComplianceDataAssetView,
      action: () => this.service.updateDataAsset(command),
    });
  }

  @Post("data-assets/:dataAssetId/status")
  @HttpCode(201)
  transitionDataAsset(
    @Param("dataAssetId") dataAssetId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    return this.statusWrite<ComplianceDataAsset, ComplianceDataAssetView>({
      context: this.context(request),
      body,
      response,
      idempotencyKey,
      resource: "dataAsset",
      resourceId: dataAssetId,
      operation: "dataAsset.transition",
      toView: toComplianceDataAssetView,
      call: (command) => this.service.transitionDataAsset(command),
    });
  }

  @Get("consents")
  async listConsentRecords(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, LIST_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, { action: "read", resource: "consentRecord" });
    const page = await this.service.listConsentRecords({
      ...this.listQuery(value),
      tenantId,
    });
    return toCompliancePageView(page, toComplianceConsentRecordView);
  }

  @Get("consents/:consentId")
  async getConsentRecord(
    @Param("consentId") consentId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, TENANT_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "consentRecord",
      resourceId: consentId,
    });
    const record = await this.service.getConsentRecord(tenantId, consentId);
    if (record === undefined) throw complianceResourceNotFound("consentRecord");
    return toComplianceConsentRecordView(record);
  }

  @Post("consents")
  @HttpCode(201)
  createConsentRecord(
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: CreateConsentRecordCommand = {
      tenantId,
      subjectRef: value.subjectRef as string,
      purpose: value.purpose as string,
      policyVersion: value.policyVersion as string,
      channel: value.channel as CreateConsentRecordCommand["channel"],
      ...this.optional(value, "subjectCount"),
      ...this.optional(value, "language"),
      ...this.optional(value, "scopes"),
      ...this.optional(value, "dataAssetIds"),
      ...this.optional(value, "expiresAt"),
      ...this.optional(value, "status"),
      ...this.optional(value, "grantedAt"),
      ...this.optional(value, "proof"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "create",
        resource: "consentRecord",
        metadata: { operation: "consentRecord.create", status: "pending" },
      },
      idempotencyKey,
      operation: "consentRecord.create",
      request: command,
      toView: toComplianceConsentRecordView,
      action: () => this.service.createConsentRecord(command),
    });
  }

  @Post("consents/:consentId/grant")
  @HttpCode(201)
  grantConsent(
    @Param("consentId") consentId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: GrantConsentCommand = {
      tenantId,
      id: consentId,
      proof: value.proof as GrantConsentCommand["proof"],
      ...this.optional(value, "grantedAt"),
      ...this.optional(value, "expiresAt"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "approve",
        resource: "consentRecord",
        resourceId: consentId,
        metadata: { operation: "consentRecord.grant", targetStatus: "granted" },
      },
      idempotencyKey,
      operation: "consentRecord.grant",
      request: command,
      toView: toComplianceConsentRecordView,
      action: () => this.service.grantConsent(command),
    });
  }

  @Post("consents/:consentId/withdraw")
  @HttpCode(201)
  withdrawConsent(
    @Param("consentId") consentId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: WithdrawConsentCommand = {
      tenantId,
      id: consentId,
      ...this.optional(value, "withdrawnAt"),
      ...this.optional(value, "reason"),
      ...this.optional(value, "proof"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "update",
        resource: "consentRecord",
        resourceId: consentId,
        metadata: { operation: "consentRecord.withdraw", targetStatus: "withdrawn" },
      },
      idempotencyKey,
      operation: "consentRecord.withdraw",
      request: command,
      toView: toComplianceConsentRecordView,
      action: () => this.service.withdrawConsent(command),
    });
  }

  @Post("consents/:consentId/expire")
  @HttpCode(201)
  expireConsent(
    @Param("consentId") consentId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: ExpireConsentCommand = {
      tenantId,
      id: consentId,
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "update",
        resource: "consentRecord",
        resourceId: consentId,
        metadata: { operation: "consentRecord.expire", targetStatus: "expired" },
      },
      idempotencyKey,
      operation: "consentRecord.expire",
      request: command,
      toView: toComplianceConsentRecordView,
      action: () => this.service.expireConsent(command),
    });
  }

  @Get("privacy-requests")
  async listPrivacyRequests(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, LIST_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, { action: "read", resource: "privacyRequest" });
    const page = await this.service.listPrivacyRequests({
      ...this.listQuery(value),
      tenantId,
    });
    return toCompliancePageView(page, toCompliancePrivacyRequestView);
  }

  @Get("privacy-requests/:privacyRequestId")
  async getPrivacyRequest(
    @Param("privacyRequestId") privacyRequestId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, TENANT_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "privacyRequest",
      resourceId: privacyRequestId,
    });
    const record = await this.service.getPrivacyRequest(tenantId, privacyRequestId);
    if (record === undefined) throw complianceResourceNotFound("privacyRequest");
    return toCompliancePrivacyRequestView(record);
  }

  @Get("privacy-requests/:privacyRequestId/sla")
  async getPrivacyRequestSla(
    @Param("privacyRequestId") privacyRequestId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, SLA_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "privacyRequest",
      resourceId: privacyRequestId,
    });
    const [record, evaluation] = await Promise.all([
      this.service.getPrivacyRequest(tenantId, privacyRequestId),
      typeof value.at === "string"
        ? this.service.evaluatePrivacyRequestSla(tenantId, privacyRequestId, value.at)
        : this.service.evaluatePrivacyRequestSla(tenantId, privacyRequestId),
    ]);
    if (record === undefined) throw complianceResourceNotFound("privacyRequest");
    return toCompliancePrivacyRequestSlaView(record, evaluation);
  }

  @Post("privacy-requests")
  @HttpCode(201)
  createPrivacyRequest(
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: CreatePrivacyRequestCommand = {
      tenantId,
      requestType: value.requestType as CreatePrivacyRequestCommand["requestType"],
      subjectRef: value.subjectRef as string,
      ...this.optional(value, "subjectCount"),
      ...this.optional(value, "dataAssetIds"),
      ...this.optional(value, "receivedAt"),
      ...this.optional(value, "responseDays"),
      ...this.optional(value, "policyCode"),
      ...this.optional(value, "duplicateOfId"),
    };
    return this.write({
      context,
      response,
      write: {
        action: "create",
        resource: "privacyRequest",
        metadata: { operation: "privacyRequest.create", status: "submitted" },
      },
      idempotencyKey,
      operation: "privacyRequest.create",
      request: command,
      toView: toCompliancePrivacyRequestView,
      action: () => this.service.createPrivacyRequest(command),
    });
  }

  @Post("privacy-requests/:privacyRequestId/identity-verification")
  @HttpCode(201)
  recordIdentityVerification(
    @Param("privacyRequestId") privacyRequestId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: RecordIdentityVerificationCommand = {
      tenantId,
      id: privacyRequestId,
      status: value.status as RecordIdentityVerificationCommand["status"],
      ...this.optional(value, "method"),
      ...this.optional(value, "verifiedByRef"),
      ...this.optional(value, "evidence"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "record",
        resource: "privacyRequest",
        resourceId: privacyRequestId,
        metadata: { operation: "privacyRequest.verifyIdentity" },
      },
      idempotencyKey,
      operation: "privacyRequest.verifyIdentity",
      request: command,
      toView: toCompliancePrivacyRequestView,
      action: () => this.service.recordIdentityVerification(command),
    });
  }

  @Post("privacy-requests/:privacyRequestId/decision")
  @HttpCode(201)
  decidePrivacyRequest(
    @Param("privacyRequestId") privacyRequestId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: DecidePrivacyRequestCommand = {
      tenantId,
      id: privacyRequestId,
      decision: value.decision as DecidePrivacyRequestCommand["decision"],
      evidence: value.evidence as DecidePrivacyRequestCommand["evidence"],
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
      ...this.optional(value, "rationale"),
      ...this.optional(value, "targetStatus"),
    };
    return this.write({
      context,
      response,
      write: {
        action: "approve",
        resource: "privacyRequest",
        resourceId: privacyRequestId,
        metadata: { operation: "privacyRequest.decide" },
      },
      idempotencyKey,
      operation: "privacyRequest.decide",
      request: command,
      toView: toCompliancePrivacyRequestView,
      action: () => this.service.decidePrivacyRequest(command),
    });
  }

  @Post("privacy-requests/:privacyRequestId/actions")
  @HttpCode(201)
  recordPrivacyRequestAction(
    @Param("privacyRequestId") privacyRequestId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: RecordPrivacyRequestActionCommand = {
      tenantId,
      id: privacyRequestId,
      action: value.action as RecordPrivacyRequestActionCommand["action"],
      dataAssetId: value.dataAssetId as string,
      ...this.optional(value, "executedAt"),
      ...this.optional(value, "affectedRecords"),
      ...this.optional(value, "executionRef"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "record",
        resource: "privacyRequest",
        resourceId: privacyRequestId,
        metadata: { operation: "privacyRequest.recordAction" },
      },
      idempotencyKey,
      operation: "privacyRequest.recordAction",
      request: command,
      toView: toCompliancePrivacyRequestView,
      action: () => this.service.recordPrivacyRequestAction(command),
    });
  }

  @Post("privacy-requests/:privacyRequestId/status")
  @HttpCode(201)
  transitionPrivacyRequest(
    @Param("privacyRequestId") privacyRequestId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    return this.statusWrite<CompliancePrivacyRequest, CompliancePrivacyRequestView>({
      context: this.context(request),
      body,
      response,
      idempotencyKey,
      resource: "privacyRequest",
      resourceId: privacyRequestId,
      operation: "privacyRequest.transition",
      toView: toCompliancePrivacyRequestView,
      call: (command) => this.service.transitionPrivacyRequest(command),
    });
  }

  @Get("retention-policies")
  async listRetentionPolicies(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, LIST_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, { action: "read", resource: "retentionPolicy" });
    const page = await this.service.listRetentionPolicies({
      ...this.listQuery(value),
      tenantId,
    });
    return toCompliancePageView(page, toComplianceRetentionPolicyView);
  }

  @Get("retention-policies/:retentionPolicyId")
  async getRetentionPolicy(
    @Param("retentionPolicyId") retentionPolicyId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, TENANT_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "retentionPolicy",
      resourceId: retentionPolicyId,
    });
    const record = await this.service.getRetentionPolicy(tenantId, retentionPolicyId);
    if (record === undefined) throw complianceResourceNotFound("retentionPolicy");
    return toComplianceRetentionPolicyView(record);
  }

  @Post("retention-policies")
  @HttpCode(201)
  createRetentionPolicy(
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: CreateRetentionPolicyCommand = {
      tenantId,
      name: value.name as string,
      code: value.code as string,
      trigger: value.trigger as CreateRetentionPolicyCommand["trigger"],
      action: value.action as CreateRetentionPolicyCommand["action"],
      retentionDays: value.retentionDays as number,
      requiresApproval: value.requiresApproval as boolean,
      legalHold: value.legalHold as boolean,
      ...this.optional(value, "dataAssetIds"),
      ...this.optional(value, "residencyRegions"),
      ...this.optional(value, "evidence"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "create",
        resource: "retentionPolicy",
        metadata: { operation: "retentionPolicy.create", status: "draft" },
      },
      idempotencyKey,
      operation: "retentionPolicy.create",
      request: command,
      toView: toComplianceRetentionPolicyView,
      action: () => this.service.createRetentionPolicy(command),
    });
  }

  @Post("retention-policies/:retentionPolicyId/status")
  @HttpCode(201)
  transitionRetentionPolicy(
    @Param("retentionPolicyId") retentionPolicyId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    return this.statusWrite<ComplianceRetentionPolicy, ComplianceRetentionPolicyView>({
      context: this.context(request),
      body,
      response,
      idempotencyKey,
      resource: "retentionPolicy",
      resourceId: retentionPolicyId,
      operation: "retentionPolicy.transition",
      approve: true,
      toView: toComplianceRetentionPolicyView,
      call: (command) => this.service.transitionRetentionPolicy(command),
    });
  }

  @Get("retention-executions")
  async listRetentionExecutions(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, LIST_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "retentionExecution",
    });
    const page = await this.service.listRetentionExecutions({
      ...this.listQuery(value),
      tenantId,
    });
    return toCompliancePageView(page, toComplianceRetentionExecutionView);
  }

  @Post("retention-executions")
  @HttpCode(201)
  recordRetentionExecution(
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: RecordRetentionExecutionCommand = {
      tenantId,
      policyId: value.policyId as string,
      status: value.status as RecordRetentionExecutionCommand["status"],
      ...this.optional(value, "runId"),
      ...this.optional(value, "dataAssetIds"),
      ...this.optional(value, "action"),
      ...this.optional(value, "occurredAt"),
      ...this.optional(value, "blockedReason"),
      ...this.optional(value, "recordsScanned"),
      ...this.optional(value, "recordsDeleted"),
      ...this.optional(value, "recordsAnonymized"),
      ...this.optional(value, "recordsArchived"),
      ...this.optional(value, "completedAt"),
      ...this.optional(value, "failureReason"),
      ...this.optional(value, "evidence"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "record",
        resource: "retentionExecution",
        metadata: { operation: "retentionExecution.record" },
      },
      idempotencyKey,
      operation: "retentionExecution.record",
      request: command,
      toView: toComplianceRetentionExecutionView,
      action: () => this.service.recordRetentionExecution(command),
    });
  }

  @Get("cross-border-assessments")
  async listCrossBorderAssessments(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, LIST_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "crossBorderAssessment",
    });
    const page = await this.service.listCrossBorderAssessments({
      ...this.listQuery(value),
      tenantId,
    });
    return toCompliancePageView(page, toComplianceCrossBorderAssessmentView);
  }

  @Get("cross-border-assessments/:crossBorderAssessmentId")
  async getCrossBorderAssessment(
    @Param("crossBorderAssessmentId") crossBorderAssessmentId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, TENANT_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "crossBorderAssessment",
      resourceId: crossBorderAssessmentId,
    });
    const record = await this.service.getCrossBorderAssessment(
      tenantId,
      crossBorderAssessmentId,
    );
    if (record === undefined) throw complianceResourceNotFound("crossBorderAssessment");
    return toComplianceCrossBorderAssessmentView(record);
  }

  @Post("cross-border-assessments")
  @HttpCode(201)
  createCrossBorderAssessment(
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: CreateCrossBorderAssessmentCommand = {
      tenantId,
      title: value.title as string,
      code: value.code as string,
      sourceRegion: value.sourceRegion as string,
      destinationRegions: value.destinationRegions as string[],
      transferPurpose: value.transferPurpose as string,
      ...this.optional(value, "dataAssetIds"),
      ...this.optional(value, "personalData"),
      ...this.optional(value, "sensitivePersonalData"),
      ...this.optional(value, "riskLevel"),
      ...this.optional(value, "riskFactors"),
      ...this.optional(value, "mechanisms"),
      ...this.optional(value, "recipientVendorId"),
      ...this.optional(value, "validUntil"),
      ...this.optional(value, "evidence"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "create",
        resource: "crossBorderAssessment",
        metadata: { operation: "crossBorderAssessment.create", status: "draft" },
      },
      idempotencyKey,
      operation: "crossBorderAssessment.create",
      request: command,
      toView: toComplianceCrossBorderAssessmentView,
      action: () => this.service.createCrossBorderAssessment(command),
    });
  }

  @Post("cross-border-assessments/:crossBorderAssessmentId/status")
  @HttpCode(201)
  transitionCrossBorderAssessment(
    @Param("crossBorderAssessmentId") crossBorderAssessmentId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    return this.statusWrite<ComplianceCrossBorderAssessment, ComplianceCrossBorderAssessmentView>({
      context: this.context(request),
      body,
      response,
      idempotencyKey,
      resource: "crossBorderAssessment",
      resourceId: crossBorderAssessmentId,
      operation: "crossBorderAssessment.transition",
      toView: toComplianceCrossBorderAssessmentView,
      call: (command) => this.service.transitionCrossBorderAssessment(command),
    });
  }

  @Post("cross-border-assessments/:crossBorderAssessmentId/decision")
  @HttpCode(201)
  decideCrossBorderAssessment(
    @Param("crossBorderAssessmentId") crossBorderAssessmentId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: TransitionCrossBorderCommand = {
      tenantId,
      id: crossBorderAssessmentId,
      targetStatus: value.targetStatus as TransitionCrossBorderCommand["targetStatus"],
      ...this.optional(value, "riskLevel"),
      ...this.optional(value, "riskFactors"),
      ...this.optional(value, "mechanisms"),
      ...this.optional(value, "evidence"),
      ...this.optional(value, "validUntil"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "approve",
        resource: "crossBorderAssessment",
        resourceId: crossBorderAssessmentId,
        metadata: { operation: "crossBorderAssessment.decide" },
      },
      idempotencyKey,
      operation: "crossBorderAssessment.decide",
      request: command,
      toView: toComplianceCrossBorderAssessmentView,
      action: () => this.service.transitionCrossBorderAssessment(command),
    });
  }

  @Get("vendors")
  async listVendors(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, LIST_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, { action: "read", resource: "vendor" });
    const page = await this.service.listVendors({
      ...this.listQuery(value),
      tenantId,
    });
    return toCompliancePageView(page, toComplianceVendorView);
  }

  @Get("vendors/:vendorId")
  async getVendor(
    @Param("vendorId") vendorId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, TENANT_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "vendor",
      resourceId: vendorId,
    });
    const record = await this.service.getVendor(tenantId, vendorId);
    if (record === undefined) throw complianceResourceNotFound("vendor");
    return toComplianceVendorView(record);
  }

  @Post("vendors")
  @HttpCode(201)
  createVendor(
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: CreateVendorCommand = {
      tenantId,
      role: value.role as CreateVendorCommand["role"],
      code: value.code as string,
      legalName: value.legalName as string,
      regions: value.regions as string[],
      ...this.optional(value, "displayName"),
      ...this.optional(value, "dataAssetIds"),
      ...this.optional(value, "dataCategories"),
      ...this.optional(value, "parentVendorId"),
      ...this.optional(value, "crossBorder"),
      ...this.optional(value, "contractEffectiveAt"),
      ...this.optional(value, "evidence"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "create",
        resource: "vendor",
        metadata: { operation: "vendor.create", status: "draft" },
      },
      idempotencyKey,
      operation: "vendor.create",
      request: command,
      toView: toComplianceVendorView,
      action: () => this.service.createVendor(command),
    });
  }

  @Post("vendors/:vendorId/status")
  @HttpCode(201)
  transitionVendor(
    @Param("vendorId") vendorId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    return this.statusWrite<ComplianceVendor, ComplianceVendorView>({
      context: this.context(request),
      body,
      response,
      idempotencyKey,
      resource: "vendor",
      resourceId: vendorId,
      operation: "vendor.transition",
      toView: toComplianceVendorView,
      call: (command) => this.service.transitionVendor(command),
    });
  }

  @Post("vendors/:vendorId/assessments")
  @HttpCode(201)
  recordVendorAssessment(
    @Param("vendorId") vendorId: string,
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: RecordVendorAssessmentCommand = {
      tenantId,
      id: vendorId,
      status: value.status as RecordVendorAssessmentCommand["status"],
      ...this.optional(value, "assessedByRef"),
      ...this.optional(value, "evidence"),
      actor: { type: "user", id: context.actorId },
      requestId: context.requestId,
    };
    return this.write({
      context,
      response,
      write: {
        action: "record",
        resource: "vendor",
        resourceId: vendorId,
        metadata: { operation: "vendor.recordAssessment" },
      },
      idempotencyKey,
      operation: "vendor.recordAssessment",
      request: command,
      toView: toComplianceVendorView,
      action: () => this.service.recordVendorAssessment(command),
    });
  }

  @Get("report")
  async getComplianceReport(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, REPORT_QUERY_KEYS);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, { action: "read", resource: "report" });
    const report = await this.service.generateComplianceReport({
      tenantId,
      from: value.from as string,
      to: value.to as string,
      ...this.optional(value, "generatedAt"),
    });
    return toComplianceReportView(report);
  }

  @Post("report")
  @HttpCode(201)
  createComplianceReport(
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: ComplianceWriteResponse,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command = {
      tenantId,
      from: value.from as string,
      to: value.to as string,
      ...this.optional(value, "generatedAt"),
    };
    return this.write({
      context,
      response,
      write: {
        action: "create",
        resource: "report",
        metadata: { operation: "report.generate" },
      },
      idempotencyKey,
      operation: "report.generate",
      request: command,
      toView: toComplianceReportView,
      action: () => this.service.generateComplianceReport(command),
    });
  }

  private context(request: OpenPlatformHttpRequest): OpenPlatformRequestContext {
    const value = request[OPEN_PLATFORM_HTTP_CONTEXT];
    if (!isOpenPlatformRequestContext(value)) throw authenticationRequired();
    return value;
  }

  private tenant(
    context: OpenPlatformRequestContext,
    body: Record<string, unknown>,
    query: Record<string, unknown> = {},
  ): string {
    for (const value of [body.tenantId, body.tenant_id, query.tenantId, query.tenant_id]) {
      if (value !== undefined && value !== context.tenantId) {
        throw tenantMismatch();
      }
    }
    return context.tenantId;
  }

  private idempotencyKey(value: string | string[] | undefined): string {
    const raw = Array.isArray(value) ? value[0] : value;
    if (raw === undefined) {
      throw complianceValidationError("Idempotency-Key is required", "idempotencyKey");
    }
    return normalizeComplianceIdempotencyKey(raw);
  }

  private body(value: unknown): Record<string, unknown> {
    return isOpenPlatformHttpRecord(value) ? value : {};
  }

  private query(
    value: unknown,
    allowed: readonly string[],
  ): Record<string, unknown> {
    if (!isOpenPlatformHttpRecord(value)) return {};
    for (const key of Object.keys(value)) {
      if (!allowed.includes(key)) {
        throw complianceValidationError("Compliance query parameter is invalid", key);
      }
    }
    return value;
  }

  private listQuery(value: Record<string, unknown>): Record<string, unknown> {
    const limit = value.limit ?? value.pageSize;
    return {
      ...(value.status === undefined ? {} : { status: value.status }),
      ...(value.ids === undefined ? {} : { ids: complianceIdList(value.ids) }),
      ...(value.cursor === undefined ? {} : { cursor: value.cursor }),
      ...(limit === undefined ? {} : { limit }),
    };
  }

  private optional(
    value: Record<string, unknown>,
    key: string,
  ): Record<string, unknown> {
    return Object.prototype.hasOwnProperty.call(value, key)
      ? { [key]: value[key] }
      : {};
  }

  private optionalNullable(
    value: Record<string, unknown>,
    key: string,
  ): Record<string, unknown> {
    return Object.prototype.hasOwnProperty.call(value, key)
      ? { [key]: value[key] ?? null }
      : {};
  }

  private async write<TRecord, TView>(input: {
    readonly context: OpenPlatformRequestContext;
    readonly response: ComplianceWriteResponse;
    readonly write: ComplianceWriteAudit;
    readonly idempotencyKey: string | string[] | undefined;
    readonly operation: string;
    readonly request: unknown;
    readonly toView: (record: TRecord) => TView;
    readonly action: () => Promise<TRecord>;
  }): Promise<TView> {
    const { context, response, write } = input;
    await this.security.authorize(context, {
      action: write.action,
      resource: write.resource,
      ...(write.resourceId === undefined ? {} : { resourceId: write.resourceId }),
    });
    const metadata = {
      ...(write.metadata ?? {}),
      operation: input.operation,
    };
    const result = await this.idempotency.execute(context, {
      operation: input.operation,
      key: this.idempotencyKey(input.idempotencyKey),
      request: input.request,
      action: async () => {
        try {
          const record = await input.action();
          const resourceId = targetId(write.resource, record);
          await this.security.recordWrite(context, {
            ...write,
            ...(resourceId === undefined ? {} : { resourceId }),
            metadata: { ...metadata, replayed: false },
          });
          return record;
        } catch (error) {
          await this.security.recordFailure(context, { ...write, metadata });
          throw error;
        }
      },
    });
    if (result.replayed) {
      response.setHeader?.(COMPLIANCE_IDEMPOTENCY_REPLAY_HEADER, "true");
    }
    return input.toView(result.value);
  }

  private statusWrite<TRecord, TView>(input: {
    readonly context: OpenPlatformRequestContext;
    readonly body: unknown;
    readonly response: ComplianceWriteResponse;
    readonly idempotencyKey: string | string[] | undefined;
    readonly resource: ComplianceStatusResource;
    readonly resourceId: string;
    readonly operation: string;
    readonly approve?: boolean;
    readonly toView: (record: TRecord) => TView;
    readonly call: (command: never) => Promise<TRecord>;
  }): Promise<TView> {
    const value = this.body(input.body);
    const tenantId = this.tenant(input.context, value);
    const targetStatus = value.targetStatus;
    if (typeof targetStatus !== "string") {
      throw complianceValidationError("Compliance target status is required", "targetStatus");
    }
    const command = {
      tenantId,
      id: input.resourceId,
      targetStatus,
      ...this.optional(value, "statusReason"),
      ...this.optional(value, "riskLevel"),
      ...this.optional(value, "riskFactors"),
      ...this.optional(value, "mechanisms"),
      ...this.optional(value, "evidence"),
      ...this.optional(value, "validUntil"),
      ...this.optional(value, "contractTerminatedAt"),
      actor: { type: "user", id: input.context.actorId },
      requestId: input.context.requestId,
    };
    return this.write({
      context: input.context,
      response: input.response,
      write: {
        action: input.approve === true ? "approve" : "update",
        resource: input.resource,
        resourceId: input.resourceId,
        metadata: { targetStatus },
      },
      idempotencyKey: input.idempotencyKey,
      operation: input.operation,
      request: command,
      toView: input.toView,
      action: () => input.call(command as never),
    });
  }
}

export { OpenPlatformComplianceController as ComplianceController };

function complianceIdList(value: unknown): string[] {
  const items = typeof value === "string" ? value.split(",") : value;
  if (!Array.isArray(items) || items.length > COMPLIANCE_MAX_PAGE_SIZE) {
    throw complianceValidationError("Compliance query parameter is invalid", "ids");
  }
  return items.map((item) => {
    if (typeof item !== "string") {
      throw complianceValidationError("Compliance query parameter is invalid", "ids");
    }
    return item.trim();
  });
}

function targetId(
  resource: ComplianceWriteResource,
  record: unknown,
): string | undefined {
  if (record === null || typeof record !== "object") return undefined;
  if (resource === "report") return `report_${(record as { readonly period?: { readonly to?: string } }).period?.to ?? "unknown"}`;
  const id = (record as { readonly id?: unknown }).id;
  return typeof id === "string" ? id : undefined;
}
