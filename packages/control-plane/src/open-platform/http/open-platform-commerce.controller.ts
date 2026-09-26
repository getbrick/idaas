import {
  Body,
  Controller,
  Get,
  Inject,
  Param,
  Post,
  Query,
  Req,
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
  OPEN_PLATFORM_COMMERCE_SERVICE,
} from "./open-platform-commerce.tokens.js";
import { OpenPlatformCommerceSecurity } from "./open-platform-commerce.security.js";
import {
  toCommerceMarketplaceListingView,
} from "../commerce/read.js";
import {
  normalizeIdempotencyKey,
} from "../commerce/validation.js";
import {
  commerceValidationError,
} from "../commerce/errors.js";
import type {
  CommissionRuleQuery,
  CreateMarketplaceListingCommand,
  DecideInvoiceDisputeCommand,
  DisputeInvoiceCommand,
  InvoiceDisputeQuery,
  InvoiceDisputeResult,
  InvoiceQuery,
  MarketplaceListingQuery,
  MarketplaceListingStatus,
  PartnerAccountQuery,
  ReviewInvoiceDisputeCommand,
  TransitionCommerceResourceCommand,
  WithdrawInvoiceDisputeCommand,
} from "../commerce/types.js";
import { OpenPlatformHttpContextGuard } from "./open-platform-http.guard.js";
import { OpenPlatformCommerceHttpExceptionFilter } from "./open-platform-commerce.filter.js";
import { OpenPlatformHttpResponseInterceptor } from "./open-platform-http.interceptor.js";
import {
  OPEN_PLATFORM_HTTP_BASE_PATH,
  OPEN_PLATFORM_HTTP_CONTEXT,
  isOpenPlatformHttpRecord,
  type OpenPlatformHttpRequest,
} from "./open-platform-http.types.js";
import type { OpenPlatformCommerceService } from "./open-platform-commerce.tokens.js";

@Controller(OPEN_PLATFORM_HTTP_BASE_PATH)
@UseGuards(OpenPlatformHttpContextGuard)
@UseFilters(OpenPlatformCommerceHttpExceptionFilter)
@UseInterceptors(OpenPlatformHttpResponseInterceptor)
export class OpenPlatformCommerceController {
  constructor(
    @Inject(OPEN_PLATFORM_COMMERCE_SERVICE)
    private readonly service: OpenPlatformCommerceService,
    @Inject(OpenPlatformCommerceSecurity)
    private readonly security: OpenPlatformCommerceSecurity,
  ) {}

  @Get("marketplace/listings")
  async listMarketplaceListings(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, [
      "tenantId",
      "tenant_id",
      "id",
      "status",
      "partnerAccountId",
      "productId",
      "search",
      "q",
      "cursor",
      "limit",
      "pageSize",
    ]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "marketplaceListing",
    });
    return this.service.listMarketplaceListings({
      ...this.queryValue(value),
      tenantId,
    } as MarketplaceListingQuery);
  }

  @Get("listings")
  listListingsAlias(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listMarketplaceListings(query, request);
  }

  @Get("marketplace/listings/:listingId")
  async getMarketplaceListing(
    @Param("listingId") listingId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, ["tenantId", "tenant_id"]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "marketplaceListing",
      resourceId: listingId,
    });
    return this.service.getMarketplaceListing({
      tenantId,
      id: listingId,
    });
  }

  @Get("marketplace/listings/:listingId/commission-rules")
  async listListingCommissionRules(
    @Param("listingId") listingId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, [
      "tenantId",
      "tenant_id",
      "status",
      "partnerAccountId",
      "cursor",
      "limit",
      "pageSize",
    ]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "commissionRule",
      resourceId: listingId,
    });
    return this.service.listCommissionRules({
      ...this.queryValue(value),
      listingId,
      tenantId,
    } as CommissionRuleQuery);
  }

  @Post("marketplace/listings")
  async createMarketplaceListing(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: CreateMarketplaceListingCommand = {
      tenantId,
      partnerAccountId: value.partnerAccountId as string,
      productId: value.productId as string,
      title: value.title as string,
      description: value.description as string,
      ...this.optional(value, "priceIds"),
      ...this.optional(value, "commissionRuleIds"),
      idempotencyKey: this.idempotencyKey(request),
      actorId: context.actorId,
    };
    await this.security.authorize(context, {
      action: "create",
      resource: "marketplaceListing",
    });
    const listing = await this.guardedWrite(
      context,
      { action: "create", resource: "marketplaceListing", metadata: { status: "draft" } },
      (created) => created.id,
      () => this.service.createMarketplaceListing(command),
    );
    if (listing.kind !== "marketplaceListing") {
      throw commerceValidationError("Marketplace listing resource is invalid", "listingId");
    }
    return toCommerceMarketplaceListingView(listing);
  }

  @Post("marketplace/listings/:listingId/submit-review")
  submitMarketplaceListingReview(
    @Param("listingId") listingId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listingTransition(request, body, listingId, "pendingReview");
  }

  @Post("marketplace/listings/:listingId/submit")
  submitMarketplaceListingAlias(
    @Param("listingId") listingId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listingTransition(request, body, listingId, "pendingReview");
  }

  @Post("marketplace/listings/:listingId/publish")
  publishMarketplaceListing(
    @Param("listingId") listingId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listingTransition(request, body, listingId, "published");
  }

  @Post("marketplace/listings/:listingId/suspend")
  suspendMarketplaceListing(
    @Param("listingId") listingId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listingTransition(request, body, listingId, "suspended");
  }

  @Post("marketplace/listings/:listingId/restore")
  restoreMarketplaceListing(
    @Param("listingId") listingId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listingTransition(request, body, listingId, "published");
  }

  @Post("marketplace/listings/:listingId/remove")
  removeMarketplaceListing(
    @Param("listingId") listingId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listingTransition(request, body, listingId, "removed");
  }

  @Post("marketplace/listings/:listingId/unpublish")
  unpublishMarketplaceListing(
    @Param("listingId") listingId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listingTransition(request, body, listingId, "removed");
  }

  @Post("marketplace/listings/:listingId/lifecycle")
  async transitionMarketplaceListing(
    @Param("listingId") listingId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const targetStatus = value.targetStatus;
    if (typeof targetStatus !== "string") {
      throw commerceValidationError("Listing target status is required", "targetStatus");
    }
    return this.executeListingTransition(
      request,
      context,
      value,
      listingId,
      targetStatus as MarketplaceListingStatus,
    );
  }

  @Get("partners")
  async listPartners(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, [
      "tenantId",
      "tenant_id",
      "id",
      "status",
      "partnerCode",
      "search",
      "q",
      "cursor",
      "limit",
      "pageSize",
    ]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "partnerAccount",
    });
    return this.service.listPartnerAccounts({
      ...this.queryValue(value),
      tenantId,
    } as PartnerAccountQuery);
  }

  @Get("partner-accounts")
  listPartnerAccountsAlias(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listPartners(query, request);
  }

  @Get("marketplace/partners")
  listMarketplacePartnersAlias(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listPartners(query, request);
  }

  @Get("partners/:partnerId")
  async getPartner(
    @Param("partnerId") partnerId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, ["tenantId", "tenant_id"]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "partnerAccount",
      resourceId: partnerId,
    });
    return this.service.getPartnerAccount({
      tenantId,
      id: partnerId,
    });
  }

  @Get("marketplace/partners/:partnerId")
  getMarketplacePartnerAlias(
    @Param("partnerId") partnerId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.getPartner(partnerId, query, request);
  }

  @Get("partners/:partnerId/commission-rules")
  async listPartnerCommissionRules(
    @Param("partnerId") partnerId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, [
      "tenantId",
      "tenant_id",
      "status",
      "listingId",
      "cursor",
      "limit",
      "pageSize",
    ]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "commissionRule",
      resourceId: partnerId,
    });
    return this.service.listCommissionRules({
      ...this.queryValue(value),
      partnerAccountId: partnerId,
      tenantId,
    } as CommissionRuleQuery);
  }

  @Get("commission-rules")
  async listCommissionRules(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, [
      "tenantId",
      "tenant_id",
      "id",
      "status",
      "listingId",
      "partnerAccountId",
      "cursor",
      "limit",
      "pageSize",
    ]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "commissionRule",
    });
    return this.service.listCommissionRules({
      ...this.queryValue(value),
      tenantId,
    } as CommissionRuleQuery);
  }

  @Get("marketplace/commission-rules")
  listMarketplaceCommissionRulesAlias(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listCommissionRules(query, request);
  }

  @Get("commission-rules/:commissionRuleId")
  async getCommissionRule(
    @Param("commissionRuleId") commissionRuleId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, ["tenantId", "tenant_id"]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "commissionRule",
      resourceId: commissionRuleId,
    });
    return this.service.getCommissionRule({
      tenantId,
      id: commissionRuleId,
    });
  }

  @Get("marketplace/commission-rules/:commissionRuleId")
  getMarketplaceCommissionRuleAlias(
    @Param("commissionRuleId") commissionRuleId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.getCommissionRule(commissionRuleId, query, request);
  }

  @Get("billing/accounts")
  async listBillingAccounts(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, [
      "tenantId",
      "tenant_id",
      "id",
      "status",
      "partnerCode",
      "search",
      "q",
      "cursor",
      "limit",
      "pageSize",
    ]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "partnerAccount",
    });
    return this.service.listBillingAccounts({
      ...this.queryValue(value),
      tenantId,
    } as PartnerAccountQuery);
  }

  @Get("billing/accounts/:accountId")
  async getBillingAccount(
    @Param("accountId") accountId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, ["tenantId", "tenant_id"]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "partnerAccount",
      resourceId: accountId,
    });
    return this.service.getBillingAccount({
      tenantId,
      id: accountId,
    });
  }

  @Get("billing/invoices")
  async listInvoices(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, [
      "tenantId",
      "tenant_id",
      "id",
      "subscriptionId",
      "planId",
      "status",
      "periodStart",
      "periodEnd",
      "from",
      "to",
      "cursor",
      "limit",
      "pageSize",
    ]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "invoice",
    });
    return this.service.listInvoices({
      ...this.queryValue(value),
      tenantId,
    } as InvoiceQuery);
  }

  @Get("billing/invoices/:invoiceId")
  async getInvoice(
    @Param("invoiceId") invoiceId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, ["tenantId", "tenant_id"]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "invoice",
      resourceId: invoiceId,
    });
    return this.service.getInvoice({
      tenantId,
      id: invoiceId,
    });
  }

  @Post("billing/invoices/:invoiceId/disputes")
  disputeInvoice(
    @Param("invoiceId") invoiceId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.createDispute(request, body, invoiceId);
  }

  @Post("billing/invoices/:invoiceId/dispute")
  disputeInvoiceAlias(
    @Param("invoiceId") invoiceId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.createDispute(request, body, invoiceId);
  }

  @Get("billing/invoices/:invoiceId/disputes")
  async listInvoiceDisputes(
    @Param("invoiceId") invoiceId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, [
      "tenantId",
      "tenant_id",
      "status",
      "from",
      "to",
      "cursor",
      "limit",
      "pageSize",
    ]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "invoice",
      resourceId: invoiceId,
    });
    return this.service.listInvoiceDisputes({
      ...this.queryValue(value),
      invoiceId,
      tenantId,
    } as InvoiceDisputeQuery);
  }

  @Get("billing/disputes/:disputeId")
  async getInvoiceDispute(
    @Param("disputeId") disputeId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.query(query, ["tenantId", "tenant_id"]);
    const tenantId = this.tenant(context, {}, value);
    await this.security.authorize(context, {
      action: "read",
      resource: "invoice",
      resourceId: disputeId,
    });
    return this.service.getInvoiceDispute({ tenantId, id: disputeId });
  }

  @Get("billing/invoice-disputes/:disputeId")
  getInvoiceDisputeAlias(
    @Param("disputeId") disputeId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.getInvoiceDispute(disputeId, query, request);
  }

  @Post("billing/invoices/:invoiceId/disputes/:disputeId/review")
  startInvoiceDisputeReview(
    @Param("invoiceId") invoiceId: string,
    @Param("disputeId") disputeId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.adjudicateDispute(
      request,
      invoiceId,
      disputeId,
      "dispute.review",
      () => {
        const context = this.context(request);
        const command: ReviewInvoiceDisputeCommand = {
          tenantId: this.tenant(context, this.body(body)),
          invoiceId,
          disputeId,
          idempotencyKey: this.idempotencyKey(request),
          actorId: context.actorId,
        };
        return this.service.startInvoiceDisputeReview(command);
      },
    );
  }

  @Post("billing/invoices/:invoiceId/disputes/:disputeId/decisions")
  decideInvoiceDispute(
    @Param("invoiceId") invoiceId: string,
    @Param("disputeId") disputeId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.adjudicateDispute(
      request,
      invoiceId,
      disputeId,
      "dispute.decide",
      () => {
        const context = this.context(request);
        const value = this.body(body);
        const outcome = value.outcome;
        if (
          outcome !== "accepted" &&
          outcome !== "rejected" &&
          outcome !== "withdrawn"
        ) {
          throw commerceValidationError(
            "Dispute decision outcome is invalid",
            "outcome",
          );
        }
        const command: DecideInvoiceDisputeCommand = {
          tenantId: this.tenant(context, value),
          invoiceId,
          disputeId,
          outcome,
          reference: value.reference as string,
          ...this.optional(value, "resolutionNote"),
          idempotencyKey: this.idempotencyKey(request),
          actorId: context.actorId,
        };
        return this.service.decideInvoiceDispute(command);
      },
    );
  }

  @Post("billing/invoices/:invoiceId/disputes/:disputeId/withdrawal")
  withdrawInvoiceDispute(
    @Param("invoiceId") invoiceId: string,
    @Param("disputeId") disputeId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.adjudicateDispute(
      request,
      invoiceId,
      disputeId,
      "dispute.withdraw",
      () => {
        const context = this.context(request);
        const value = this.body(body);
        const command: WithdrawInvoiceDisputeCommand = {
          tenantId: this.tenant(context, value),
          invoiceId,
          disputeId,
          reference: value.reference as string,
          ...this.optional(value, "resolutionNote"),
          idempotencyKey: this.idempotencyKey(request),
          actorId: context.actorId,
        };
        return this.service.withdrawInvoiceDispute(command);
      },
    );
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

  private idempotencyKey(request: OpenPlatformHttpRequest): string {
    const value = headerValue(request.headers, "idempotency-key");
    if (value === undefined) {
      throw commerceValidationError("Idempotency-Key is required", "idempotencyKey");
    }
    if (typeof value !== "string") {
      throw commerceValidationError("Idempotency-Key is invalid", "idempotencyKey");
    }
    return normalizeIdempotencyKey(value);
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
        throw commerceValidationError("Commerce query parameter is invalid", key);
      }
    }
    return value;
  }

  private queryValue(value: Record<string, unknown>): Record<string, unknown> {
    const output = { ...value };
    delete output.tenantId;
    delete output.tenant_id;
    return output;
  }

  private optional(
    value: Record<string, unknown>,
    key: string,
  ): Record<string, unknown> {
    return Object.prototype.hasOwnProperty.call(value, key)
      ? { [key]: value[key] }
      : {};
  }

  private async guardedWrite<T>(
    context: OpenPlatformRequestContext,
    write: {
      readonly action:
        | "create"
        | "update"
        | "record"
        | "dispute.review"
        | "dispute.decide"
        | "dispute.withdraw";
      readonly resource: "marketplaceListing" | "invoice";
      readonly metadata?: Readonly<Record<string, unknown>>;
    },
    targetId: (value: T) => string | undefined,
    action: () => Promise<T>,
  ): Promise<T> {
    try {
      const value = await action();
      const resourceId = targetId(value);
      await this.security.recordWrite(context, {
        ...write,
        ...(resourceId === undefined ? {} : { resourceId }),
      });
      return value;
    } catch (error) {
      await this.security.recordFailure(context, write);
      throw error;
    }
  }

  private async adjudicateDispute(
    request: OpenPlatformHttpRequest,
    invoiceId: string,
    disputeId: string,
    action: "dispute.review" | "dispute.decide" | "dispute.withdraw",
    execute: () => Promise<InvoiceDisputeResult>,
  ) {
    const context = this.context(request);
    await this.security.authorize(context, {
      action,
      resource: "invoice",
      resourceId: disputeId,
    });
    try {
      const result = await execute();
      const resolution = result.dispute.resolution;
      await this.security.recordWrite(context, {
        action,
        resource: "invoice",
        resourceId: result.dispute.id,
        metadata: {
          invoiceId,
          disputeId: result.dispute.id,
          fromStatus: result.fromStatus,
          toStatus: result.dispute.status,
          ...(resolution === undefined ? {} : { outcome: resolution.outcome }),
          ...(resolution?.noteLength === undefined
            ? {}
            : { noteLength: resolution.noteLength }),
          replayed: result.replayed,
        },
      });
      return result;
    } catch (error) {
      await this.security.recordFailure(context, {
        action,
        resource: "invoice",
        resourceId: disputeId,
        metadata: { invoiceId, disputeId },
      });
      throw error;
    }
  }

  private async createDispute(
    request: OpenPlatformHttpRequest,
    body: unknown,
    invoiceId: string,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command: DisputeInvoiceCommand = {
      tenantId,
      invoiceId,
      reason: value.reason as string,
      idempotencyKey: this.idempotencyKey(request),
      ...this.optional(value, "evidenceReference"),
      actorId: context.actorId,
    };
    await this.security.authorize(context, {
      action: "update",
      resource: "invoice",
      resourceId: invoiceId,
    });
    return this.guardedWrite(
      context,
      { action: "update", resource: "invoice", metadata: { targetStatus: "disputed" } },
      (result) => result.invoice.id,
      () => this.service.disputeInvoice(command),
    );
  }

  private async listingTransition(
    request: OpenPlatformHttpRequest,
    body: unknown,
    listingId: string,
    targetStatus: MarketplaceListingStatus,
  ) {
    const context = this.context(request);
    return this.executeListingTransition(
      request,
      context,
      this.body(body),
      listingId,
      targetStatus,
    );
  }

  private async executeListingTransition(
    request: OpenPlatformHttpRequest,
    context: OpenPlatformRequestContext,
    body: Record<string, unknown>,
    listingId: string,
    targetStatus: MarketplaceListingStatus,
  ) {
    const command: TransitionCommerceResourceCommand & { readonly idempotencyKey: string } = {
      tenantId: this.tenant(context, body),
      resource: "marketplaceListing",
      id: listingId,
      targetStatus,
      idempotencyKey: this.idempotencyKey(request),
      actorId: context.actorId,
    };
    await this.security.authorize(context, {
      action: "update",
      resource: "marketplaceListing",
      resourceId: listingId,
    });
    const result = await this.guardedWrite(
      context,
      {
        action: "update",
        resource: "marketplaceListing",
        metadata: { targetStatus, resourceKind: "marketplaceListing" },
      },
      (transitioned) => transitioned.record.id,
      () => this.service.transitionWithIdempotency(command),
    );
    if (result.record.kind !== "marketplaceListing") {
      throw commerceValidationError("Marketplace listing resource is invalid", "listingId");
    }
    return toCommerceMarketplaceListingView(result.record);
  }
}

export { OpenPlatformCommerceController as CommerceController };

function headerValue(
  headers: Record<string, unknown> | undefined,
  name: string,
): unknown {
  const entry = Object.entries(headers ?? {}).find(([key]) => key.toLowerCase() === name);
  return entry?.[1];
}
