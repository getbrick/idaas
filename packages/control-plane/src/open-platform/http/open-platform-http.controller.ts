import {
  Body,
  Controller,
  Get,
  HttpCode,
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
  validationError,
} from "../errors.js";
import {
  isOpenPlatformRequestContext,
  type OpenPlatformRequestContext,
} from "../authorization.js";
import type {
  CredentialDto,
  OpenPlatformLifecycleResourceKind,
  OpenPlatformWebhookCreateCommand,
} from "../types.js";
import {
  toOpenPlatformWebhookDto,
  type OpenPlatformWebhookDeliveryQuery,
} from "../webhook.js";
import { OpenPlatformService } from "../service.js";
import { OpenPlatformHttpContextGuard } from "./open-platform-http.guard.js";
import { OpenPlatformHttpExceptionFilter } from "./open-platform-http.filter.js";
import { OpenPlatformHttpResponseInterceptor } from "./open-platform-http.interceptor.js";
import {
  OPEN_PLATFORM_HTTP_BASE_PATH,
  OPEN_PLATFORM_HTTP_CONTEXT,
  isOpenPlatformHttpRecord,
  type OpenPlatformHttpRequest,
} from "./open-platform-http.types.js";

@Controller(OPEN_PLATFORM_HTTP_BASE_PATH)
@UseGuards(OpenPlatformHttpContextGuard)
@UseFilters(OpenPlatformHttpExceptionFilter)
@UseInterceptors(OpenPlatformHttpResponseInterceptor)
export class OpenPlatformHttpController {
  constructor(
    @Inject(OpenPlatformService)
    private readonly service: OpenPlatformService,
  ) {}

  @Post("tenants")
  createTenant(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.createTenant(context, {
      tenantId: this.tenant(context, value, {}, undefined),
      name: value.name as string,
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("tenants")
  listTenants(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listTenants(context, {
      tenantId: this.tenant(context, {}, query),
    });
  }

  @Get("tenants/:tenantKey")
  getTenant(
    @Param("tenantKey") tenantKey: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getTenant(context, {
      tenantId: this.tenant(context, {}, query, tenantKey),
    });
  }

  @Post("tenants/:tenantKey/publish")
  publishTenant(
    @Param("tenantKey") tenantKey: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.tenantLifecycle(request, body, tenantKey, "publish");
  }

  @Post("tenants/:tenantKey/disable")
  disableTenant(
    @Param("tenantKey") tenantKey: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.tenantLifecycle(request, body, tenantKey, "disable");
  }

  @Post("tenants/:tenantKey/deactivate")
  deactivateTenant(
    @Param("tenantKey") tenantKey: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.tenantLifecycle(request, body, tenantKey, "disable");
  }

  @Post("tenants/:tenantKey/archive")
  archiveTenant(
    @Param("tenantKey") tenantKey: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.tenantLifecycle(request, body, tenantKey, "archive");
  }

  @Post("tenants/:tenantKey/restore")
  restoreTenant(
    @Param("tenantKey") tenantKey: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.tenantLifecycle(request, body, tenantKey, "publish");
  }

  @Get("tenant-records/:tenantRecordId")
  getTenantRecord(
    @Param("tenantRecordId") tenantRecordId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getLifecycleRecord(context, "tenant", {
      tenantId: this.tenant(context, {}, query),
      id: tenantRecordId,
    });
  }

  @Post("tenant-records/:tenantRecordId/publish")
  publishTenantRecord(
    @Param("tenantRecordId") tenantRecordId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "tenant", tenantRecordId, "publish");
  }

  @Post("tenant-records/:tenantRecordId/disable")
  disableTenantRecord(
    @Param("tenantRecordId") tenantRecordId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "tenant", tenantRecordId, "disable");
  }

  @Post("tenant-records/:tenantRecordId/archive")
  archiveTenantRecord(
    @Param("tenantRecordId") tenantRecordId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "tenant", tenantRecordId, "archive");
  }

  @Post("organizations")
  createOrganization(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.createDeveloperOrganization(context, {
      tenantId: this.tenant(context, value),
      name: value.name as string,
      ...this.optional(value, "description"),
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Post("developer-organizations")
  createDeveloperOrganizationAlias(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.createOrganization(body, request);
  }

  @Get("organizations")
  listOrganizations(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listDeveloperOrganizations(context, {
      tenantId: this.tenant(context, {}, query),
      ...this.optionalQuery(query, "id"),
    });
  }

  @Get("developer-organizations")
  listDeveloperOrganizationsAlias(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listOrganizations(query, request);
  }

  @Get("organizations/:organizationId")
  getOrganization(
    @Param("organizationId") organizationId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getDeveloperOrganization(context, {
      tenantId: this.tenant(context, {}, query),
      id: organizationId,
    });
  }

  @Get("developer-organizations/:organizationId")
  getDeveloperOrganizationAlias(
    @Param("organizationId") organizationId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.getOrganization(organizationId, query, request);
  }

  @Post("organizations/:organizationId/publish")
  publishOrganization(
    @Param("organizationId") organizationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "developerOrganization", organizationId, "publish");
  }

  @Post("organizations/:organizationId/disable")
  disableOrganization(
    @Param("organizationId") organizationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "developerOrganization", organizationId, "disable");
  }

  @Post("organizations/:organizationId/archive")
  archiveOrganization(
    @Param("organizationId") organizationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "developerOrganization", organizationId, "archive");
  }

  @Post("developer-organizations/:organizationId/publish")
  publishDeveloperOrganizationAlias(
    @Param("organizationId") organizationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "developerOrganization", organizationId, "publish");
  }

  @Post("developer-organizations/:organizationId/disable")
  disableDeveloperOrganizationAlias(
    @Param("organizationId") organizationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "developerOrganization", organizationId, "disable");
  }

  @Post("developer-organizations/:organizationId/archive")
  archiveDeveloperOrganizationAlias(
    @Param("organizationId") organizationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "developerOrganization", organizationId, "archive");
  }

  @Post("applications")
  createApplication(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.createApplication(context, {
      tenantId: this.tenant(context, value),
      organizationId: value.organizationId as string,
      name: value.name as string,
      ...this.optional(value, "description"),
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("applications")
  listApplications(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listApplications(context, {
      tenantId: this.tenant(context, {}, query),
      ...this.optionalQuery(query, "id"),
    });
  }

  @Get("applications/:applicationId")
  getApplication(
    @Param("applicationId") applicationId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getApplication(context, {
      tenantId: this.tenant(context, {}, query),
      id: applicationId,
    });
  }

  @Post("applications/:applicationId/publish")
  publishApplication(
    @Param("applicationId") applicationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "application", applicationId, "publish");
  }

  @Post("applications/:applicationId/enable")
  enableApplication(
    @Param("applicationId") applicationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "application", applicationId, "publish");
  }

  @Post("applications/:applicationId/disable")
  disableApplication(
    @Param("applicationId") applicationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "application", applicationId, "disable");
  }

  @Post("applications/:applicationId/archive")
  archiveApplication(
    @Param("applicationId") applicationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "application", applicationId, "archive");
  }

  @Get("applications/:applicationId/environments")
  listEnvironments(
    @Param("applicationId") applicationId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listApplicationEnvironments(context, {
      tenantId: this.tenant(context, {}, query),
      applicationId,
      ...this.optionalQuery(query, "id"),
    });
  }

  @Post("applications/:applicationId/environments")
  createEnvironment(
    @Param("applicationId") applicationId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    this.assertBinding(value, "applicationId", applicationId);
    return this.service.createApplicationEnvironment(context, {
      tenantId: this.tenant(context, value),
      applicationId,
      name: value.name as string,
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("applications/:applicationId/environments/:environmentId")
  getEnvironment(
    @Param("applicationId") applicationId: string,
    @Param("environmentId") environmentId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getApplicationEnvironment(context, {
      tenantId: this.tenant(context, {}, query),
      applicationId,
      id: environmentId,
    });
  }

  @Post("applications/:applicationId/environments/:environmentId/publish")
  publishEnvironment(
    @Param("applicationId") applicationId: string,
    @Param("environmentId") environmentId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.environmentLifecycle(request, body, applicationId, environmentId, "publish");
  }

  @Post("applications/:applicationId/environments/:environmentId/release")
  releaseEnvironment(
    @Param("applicationId") applicationId: string,
    @Param("environmentId") environmentId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.environmentLifecycle(request, body, applicationId, environmentId, "publish");
  }

  @Post("applications/:applicationId/environments/:environmentId/disable")
  disableEnvironment(
    @Param("applicationId") applicationId: string,
    @Param("environmentId") environmentId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.environmentLifecycle(request, body, applicationId, environmentId, "disable");
  }

  @Post("applications/:applicationId/environments/:environmentId/archive")
  archiveEnvironment(
    @Param("applicationId") applicationId: string,
    @Param("environmentId") environmentId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.environmentLifecycle(request, body, applicationId, environmentId, "archive");
  }

  @Get("catalog/products")
  listProducts(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listApiProducts(context, {
      tenantId: this.tenant(context, {}, query),
      ...this.optionalQuery(query, "id"),
    });
  }

  @Post("catalog/products")
  createProduct(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.createApiProduct(context, {
      tenantId: this.tenant(context, value),
      name: value.name as string,
      ...this.optional(value, "description"),
      scopes: value.scopes as readonly string[],
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("catalog/products/:productId")
  getProduct(
    @Param("productId") productId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getApiProduct(context, {
      tenantId: this.tenant(context, {}, query),
      id: productId,
    });
  }

  @Post("catalog/products/:productId/publish")
  publishProduct(
    @Param("productId") productId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "apiProduct", productId, "publish");
  }

  @Post("catalog/products/:productId/disable")
  disableProduct(
    @Param("productId") productId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "apiProduct", productId, "disable");
  }

  @Post("catalog/products/:productId/archive")
  archiveProduct(
    @Param("productId") productId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "apiProduct", productId, "archive");
  }

  @Get("catalog/products/:productId/versions")
  listVersions(
    @Param("productId") productId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listApiVersions(context, {
      tenantId: this.tenant(context, {}, query),
      productId,
      ...this.optionalQuery(query, "id"),
    });
  }

  @Post("catalog/products/:productId/versions")
  createVersion(
    @Param("productId") productId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    this.assertBinding(value, "productId", productId);
    return this.service.createApiVersion(context, {
      tenantId: this.tenant(context, value),
      productId,
      apiVersion: value.apiVersion as string,
      ...this.optional(value, "description"),
      scopes: value.scopes as readonly string[],
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("catalog/products/:productId/versions/:versionId")
  getVersion(
    @Param("productId") productId: string,
    @Param("versionId") versionId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getApiVersion(context, {
      tenantId: this.tenant(context, {}, query),
      productId,
      id: versionId,
    });
  }

  @Post("catalog/products/:productId/versions/:versionId/publish")
  publishVersion(
    @Param("productId") productId: string,
    @Param("versionId") versionId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.versionLifecycle(request, body, productId, versionId, "publish");
  }

  @Post("catalog/products/:productId/versions/:versionId/deprecate")
  deprecateVersion(
    @Param("productId") productId: string,
    @Param("versionId") versionId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.versionLifecycle(request, body, productId, versionId, "disable");
  }

  @Post("catalog/products/:productId/versions/:versionId/disable")
  disableVersion(
    @Param("productId") productId: string,
    @Param("versionId") versionId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.versionLifecycle(request, body, productId, versionId, "disable");
  }

  @Post("catalog/products/:productId/versions/:versionId/archive")
  archiveVersion(
    @Param("productId") productId: string,
    @Param("versionId") versionId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.versionLifecycle(request, body, productId, versionId, "archive");
  }

  @Get("credentials")
  listCredentials(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listCredentials(context, {
      tenantId: this.tenant(context, {}, query),
      ...this.optionalQuery(query, "applicationId"),
      ...this.optionalQuery(query, "environmentId"),
      ...this.optionalQuery(query, "id"),
    });
  }

  @Post("credentials")
  issueCredential(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.issueCredential(context, {
      tenantId: this.tenant(context, value),
      applicationId: value.applicationId as string,
      ...this.optional(value, "environmentId"),
      name: value.name as string,
      scopes: value.scopes as readonly string[],
      ...this.optional(value, "expiresAt"),
      idempotencyKey: this.idempotencyKey(request, value),
    }).then((result) => this.credentialIssueResponse(result));
  }

  @Get("credentials/:credentialId")
  getCredential(
    @Param("credentialId") credentialId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getCredential(context, {
      tenantId: this.tenant(context, {}, query),
      id: credentialId,
    });
  }

  @Post("credentials/:credentialId/rotate")
  @HttpCode(200)
  rotateCredential(
    @Param("credentialId") credentialId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.rotateCredential(context, {
      tenantId: this.tenant(context, value),
      credentialId,
      idempotencyKey: this.idempotencyKey(request, value),
    }).then((result) => this.credentialRotationResponse(result));
  }

  @Post("credentials/:credentialId/revoke")
  @HttpCode(200)
  revokeCredential(
    @Param("credentialId") credentialId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.revokeCredential(context, {
      tenantId: this.tenant(context, value),
      credentialId,
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Post("scope-grants/authorize")
  @HttpCode(200)
  authorizeScopes(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.authorizeScopes(context, {
      tenantId: this.tenant(context, value),
      credentialId: value.credentialId as string,
      productId: value.productId as string,
      ...this.optional(value, "apiVersionId"),
      scopes: value.scopes as readonly string[],
    });
  }

  @Get("scope-grants")
  listScopeGrants(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listScopeGrants(context, {
      tenantId: this.tenant(context, {}, query),
      ...this.optionalQuery(query, "credentialId"),
      ...this.optionalQuery(query, "productId"),
      ...this.optionalQuery(query, "apiVersionId"),
      ...this.optionalQuery(query, "id"),
    });
  }

  @Post("scope-grants")
  grantScopes(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.grantScopes(context, {
      tenantId: this.tenant(context, value),
      credentialId: value.credentialId as string,
      productId: value.productId as string,
      ...this.optional(value, "apiVersionId"),
      scopes: value.scopes as readonly string[],
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("scope-grants/:scopeGrantId")
  getScopeGrant(
    @Param("scopeGrantId") scopeGrantId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getScopeGrant(context, {
      tenantId: this.tenant(context, {}, query),
      id: scopeGrantId,
    });
  }

  @Post("scope-grants/:scopeGrantId/revoke")
  @HttpCode(200)
  revokeScopeGrant(
    @Param("scopeGrantId") scopeGrantId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.revokeScopeGrant(context, {
      tenantId: this.tenant(context, value),
      scopeGrantId,
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("subscriptions")
  listSubscriptions(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listSubscriptions(context, {
      tenantId: this.tenant(context, {}, query),
      ...this.optionalQuery(query, "applicationId"),
      ...this.optionalQuery(query, "productId"),
      ...this.optionalQuery(query, "id"),
    });
  }

  @Post("subscriptions")
  createSubscription(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.createSubscription(context, {
      tenantId: this.tenant(context, value),
      applicationId: value.applicationId as string,
      productId: value.productId as string,
      ...this.optional(value, "apiVersionId"),
      name: value.name as string,
      scopes: value.scopes as readonly string[],
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("subscriptions/:subscriptionId")
  getSubscription(
    @Param("subscriptionId") subscriptionId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getSubscription(context, {
      tenantId: this.tenant(context, {}, query),
      id: subscriptionId,
    });
  }

  @Post("subscriptions/:subscriptionId/publish")
  publishSubscription(
    @Param("subscriptionId") subscriptionId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "subscription", subscriptionId, "publish");
  }

  @Post("subscriptions/:subscriptionId/disable")
  disableSubscription(
    @Param("subscriptionId") subscriptionId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "subscription", subscriptionId, "disable");
  }

  @Post("subscriptions/:subscriptionId/archive")
  archiveSubscription(
    @Param("subscriptionId") subscriptionId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.lifecycle(request, body, "subscription", subscriptionId, "archive");
  }

  @Get("usage")
  listUsage(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listUsage(context, {
      tenantId: this.tenant(context, {}, query),
      ...this.optionalQuery(query, "subscriptionId"),
      ...this.optionalQuery(query, "credentialId"),
      ...this.optionalQuery(query, "from"),
      ...this.optionalQuery(query, "to"),
    });
  }

  @Post("usage")
  recordUsage(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.recordUsage(context, {
      tenantId: this.tenant(context, value),
      subscriptionId: value.subscriptionId as string,
      metric: value.metric as string,
      quantity: value.quantity as number,
      ...this.optional(value, "occurredAt"),
      ...this.optional(value, "credentialId"),
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("authorizations")
  listAuthorizations(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.listScopeGrants(query, request);
  }

  @Post("authorizations")
  createAuthorization(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.grantScopes(body, request);
  }

  @Post("authorizations/authorize")
  @HttpCode(200)
  authorizeAuthorization(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.authorizeScopes(body, request);
  }

  @Get("authorizations/:scopeGrantId")
  getAuthorization(
    @Param("scopeGrantId") scopeGrantId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.getScopeGrant(scopeGrantId, query, request);
  }

  @Post("authorizations/:scopeGrantId/revoke")
  @HttpCode(200)
  revokeAuthorization(
    @Param("scopeGrantId") scopeGrantId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.revokeScopeGrant(scopeGrantId, body, request);
  }

  @Get("audit-events")
  listAuditEvents(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listAuditEvents(context, {
      tenantId: this.tenant(context, {}, query),
      ...this.optionalQuery(query, "cursor"),
      ...this.optionalQuery(query, "action"),
      ...this.optionalQuery(query, "outcome"),
      ...this.optionalQuery(query, "targetId"),
      ...this.optionalQuery(query, "target_id"),
      ...this.optionalLimit(query),
    } as Parameters<OpenPlatformService["listAuditEvents"]>[1]);
  }

  @Get("audit-events/:auditEventId")
  getAuditEvent(
    @Param("auditEventId") auditEventId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getAuditEvent(context, {
      tenantId: this.tenant(context, {}, query),
      id: auditEventId,
    });
  }

  @Get("webhooks")
  listWebhooks(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listWebhooks(context, {
      tenantId: this.tenant(context, {}, query),
      ...this.optionalQuery(query, "id"),
      ...this.optionalQuery(query, "status"),
      ...this.optionalQuery(query, "applicationId"),
      ...this.optionalQuery(query, "application_id"),
      ...this.optionalQuery(query, "environmentId"),
      ...this.optionalQuery(query, "environment_id"),
      ...this.optionalQuery(query, "cursor"),
      ...this.optionalLimit(query),
    } as Parameters<OpenPlatformService["listWebhooks"]>[1]).then((page) => ({
      ...page,
      items: page.items.map((webhook) => toOpenPlatformWebhookDto(webhook)),
    }));
  }

  @Post("webhooks")
  createWebhook(
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.createWebhook(context, {
      tenantId: this.tenant(context, value),
      ...(value.developerOrganizationId === undefined && value.developer_organization_id === undefined
        ? {}
        : { developerOrganizationId: (value.developerOrganizationId ?? value.developer_organization_id) as string }),
      applicationId: (value.applicationId ?? value.application_id) as string,
      environmentId: (value.environmentId ?? value.environment_id) as string,
      name: value.name as string,
      endpointUrl: (value.endpointUrl ?? value.endpoint_url) as string,
      events: value.events as readonly string[],
      idempotencyKey: this.idempotencyKey(request, value),
    }).then((result) => ({
      webhook: toOpenPlatformWebhookDto(result.webhook),
      secret: result.secret,
      secretVersion: result.secretVersion,
      ...(result.replayed === undefined ? {} : { replayed: result.replayed }),
    }));
  }

  @Get("webhooks/:webhookId/deliveries")
  listWebhookDeliveries(
    @Param("webhookId") webhookId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.listWebhookDeliveries(context, {
      tenantId: this.tenant(context, {}, query),
      webhookId,
      ...this.optionalQuery(query, "eventId"),
      ...this.optionalQuery(query, "event_id"),
      ...this.optionalQuery(query, "status"),
      ...this.optionalQuery(query, "cursor"),
      ...this.optionalLimit(query),
    } as OpenPlatformWebhookDeliveryQuery);
  }

  @Post("webhooks/:webhookId/deliveries/:deliveryId/replay")
  @HttpCode(200)
  replayWebhookDelivery(
    @Param("webhookId") webhookId: string,
    @Param("deliveryId") deliveryId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.replayWebhookDelivery(context, {
      tenantId: this.tenant(context, value),
      webhookId,
      deliveryId,
      idempotencyKey: this.idempotencyKey(request, value),
    });
  }

  @Get("webhooks/:webhookId")
  getWebhook(
    @Param("webhookId") webhookId: string,
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    return this.service.getWebhook(context, {
      tenantId: this.tenant(context, {}, query),
      id: webhookId,
    }).then((webhook) => toOpenPlatformWebhookDto(webhook));
  }

  @Post("webhooks/:webhookId/pause")
  @HttpCode(200)
  pauseWebhook(
    @Param("webhookId") webhookId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.webhookLifecycle(request, body, webhookId, "pause");
  }

  @Post("webhooks/:webhookId/disable")
  @HttpCode(200)
  disableWebhook(
    @Param("webhookId") webhookId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.webhookLifecycle(request, body, webhookId, "disable");
  }

  @Post("webhooks/:webhookId/resume")
  @HttpCode(200)
  resumeWebhook(
    @Param("webhookId") webhookId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    return this.webhookLifecycle(request, body, webhookId, "resume");
  }

  @Post("webhooks/:webhookId/rotate-secret")
  @HttpCode(200)
  rotateWebhookSecret(
    @Param("webhookId") webhookId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    return this.service.rotateWebhookSecret(context, {
      tenantId: this.tenant(context, value),
      webhookId,
      idempotencyKey: this.idempotencyKey(request, value),
    }).then((result) => ({
      webhook: toOpenPlatformWebhookDto(result.webhook),
      secret: result.secret,
      secretVersion: result.secretVersion,
      ...(result.replayed === undefined ? {} : { replayed: result.replayed }),
    }));
  }

  @Post("webhooks/:webhookId/test")
  @HttpCode(200)
  testWebhook(
    @Param("webhookId") webhookId: string,
    @Body() body: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const nestedEvent = isOpenPlatformHttpRecord(value.event) ? value.event : {};
    const event = {
      ...nestedEvent,
      tenantId: this.tenant(context, value),
      ...(value.eventId === undefined && value.event_id === undefined ? {} : { eventId: (value.eventId ?? value.event_id) as string }),
      ...(value.eventType === undefined && value.event_type === undefined && value.type === undefined ? {} : { eventType: (value.eventType ?? value.event_type ?? value.type) as string }),
      ...(value.occurredAt === undefined && value.occurred_at === undefined ? {} : { occurredAt: (value.occurredAt ?? value.occurred_at) as string }),
      ...(value.data === undefined ? {} : { data: value.data as Record<string, unknown> }),
    };
    return this.service.dispatchWebhookEvent(context, {
      tenantId: this.tenant(context, value),
      webhookId,
      event,
      idempotencyKey: this.idempotencyKey(request, value),
      ...(value.replay === true ? { replay: true } : {}),
    });
  }

  private webhookLifecycle(
    request: OpenPlatformHttpRequest,
    body: unknown,
    webhookId: string,
    action: "pause" | "disable" | "resume",
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const command = {
      tenantId: this.tenant(context, value),
      webhookId,
      idempotencyKey: this.idempotencyKey(request, value),
    };
    const result = action === "pause"
      ? this.service.pauseWebhook(context, command)
      : action === "disable"
        ? this.service.disableWebhook(context, command)
        : this.service.resumeWebhook(context, command);
    return result.then((webhook) => toOpenPlatformWebhookDto(webhook));
  }

  private optionalLimit(query: unknown): { limit?: number } {
    if (!isOpenPlatformHttpRecord(query)) return {};
    const value = query.limit ?? query.pageSize ?? query.page_size;
    if (value === undefined) return {};
    const normalized = typeof value === "number" ? value : typeof value === "string" && /^[1-9][0-9]{0,2}$/u.test(value) ? Number(value) : Number.NaN;
    if (!Number.isInteger(normalized) || normalized < 1 || normalized > 100) throw validationError("Page limit is invalid");
    return { limit: normalized };
  }

  private context(request: OpenPlatformHttpRequest): OpenPlatformRequestContext {
    const value = request[OPEN_PLATFORM_HTTP_CONTEXT];
    if (!isOpenPlatformRequestContext(value)) throw authenticationRequired();
    return value;
  }

  private tenant(
    context: OpenPlatformRequestContext,
    body: Record<string, unknown>,
    query?: unknown,
    pathTenantKey?: string,
  ): string {
    const queryValue = isOpenPlatformHttpRecord(query) ? query : {};
    for (const value of [body.tenantId, body.tenant_id, queryValue.tenantId, queryValue.tenant_id]) {
      if (value !== undefined && value !== context.tenantId) throw tenantMismatch();
    }
    if (pathTenantKey !== undefined && pathTenantKey !== context.tenantId) {
      throw tenantMismatch();
    }
    return context.tenantId;
  }

  private idempotencyKey(
    request: OpenPlatformHttpRequest,
    body: Record<string, unknown>,
  ): string {
    const header = headerValue(request.headers, "idempotency-key");
    if (header !== undefined) {
      if (typeof header !== "string") throw validationError("Idempotency-Key is invalid");
      return header;
    }
    const value = body.idempotencyKey ?? body.idempotency_key;
    if (value === undefined) throw validationError("Idempotency-Key is required");
    if (typeof value !== "string") throw validationError("Idempotency-Key is invalid");
    return value;
  }

  private body(value: unknown): Record<string, unknown> {
    return isOpenPlatformHttpRecord(value) ? value : {};
  }

  private optional(
    value: Record<string, unknown>,
    key: string,
  ): Record<string, unknown> {
    return Object.prototype.hasOwnProperty.call(value, key)
      ? { [key]: value[key] }
      : {};
  }

  private optionalQuery(
    value: unknown,
    key: string,
  ): Record<string, unknown> {
    if (!isOpenPlatformHttpRecord(value) || !Object.prototype.hasOwnProperty.call(value, key)) {
      return {};
    }
    return { [key]: value[key] };
  }

  private tenantLifecycle(
    request: OpenPlatformHttpRequest,
    body: unknown,
    tenantKey: string,
    action: "publish" | "disable" | "archive",
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value, {}, tenantKey);
    return this.service.getTenant(context, { tenantId }).then((tenant) => {
      const command = {
        resource: "tenant" as const,
        tenantId,
        id: tenant.id,
        idempotencyKey: this.idempotencyKey(request, value),
      };
      if (action === "publish") return this.service.publish(context, command);
      if (action === "disable") return this.service.deactivate(context, command);
      return this.service.archive(context, command);
    });
  }

  private lifecycle(
    request: OpenPlatformHttpRequest,
    body: unknown,
    resource: OpenPlatformLifecycleResourceKind,
    id: string,
    action: "publish" | "disable" | "archive",
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const command = {
      resource,
      tenantId: this.tenant(context, value),
      id,
      idempotencyKey: this.idempotencyKey(request, value),
    };
    if (action === "publish") return this.service.publish(context, command);
    if (action === "disable") return this.service.deactivate(context, command);
    return this.service.archive(context, command);
  }

  private environmentLifecycle(
    request: OpenPlatformHttpRequest,
    body: unknown,
    applicationId: string,
    environmentId: string,
    action: "publish" | "disable" | "archive",
  ) {
    const context = this.context(request);
    const value = this.body(body);
    this.assertBinding(value, "applicationId", applicationId);
    const tenantId = this.tenant(context, value);
    const command = {
      resource: "applicationEnvironment" as const,
      tenantId,
      id: environmentId,
      idempotencyKey: this.idempotencyKey(request, value),
    };
    return this.service.getApplicationEnvironment(context, {
      tenantId,
      applicationId,
      id: environmentId,
    }).then(() => action === "publish"
      ? this.service.publish(context, command)
      : action === "disable"
        ? this.service.deactivate(context, command)
        : this.service.archive(context, command)).then((result) => {
      if (result.kind !== "applicationEnvironment" || result.applicationId !== applicationId) {
        throw tenantMismatch();
      }
      return result;
    });
  }

  private versionLifecycle(
    request: OpenPlatformHttpRequest,
    body: unknown,
    productId: string,
    versionId: string,
    action: "publish" | "disable" | "archive",
  ) {
    const context = this.context(request);
    const value = this.body(body);
    const tenantId = this.tenant(context, value);
    const command = {
      resource: "apiVersion" as const,
      tenantId,
      id: versionId,
      idempotencyKey: this.idempotencyKey(request, value),
    };
    return this.service.getApiVersion(context, {
      tenantId,
      productId,
      id: versionId,
    }).then(() => action === "publish"
      ? this.service.publish(context, command)
      : action === "disable"
        ? this.service.deactivate(context, command)
        : this.service.archive(context, command));
  }

  private assertBinding(
    value: Record<string, unknown>,
    key: string,
    expected: string,
  ): void {
    const candidate = value[key];
    if (candidate !== undefined && candidate !== expected) {
      throw validationError("Open platform resource binding is invalid");
    }
  }

  private credentialIssueResponse(result: {
    credential: CredentialDto;
    secret: string | undefined;
    replayed: boolean;
  }): Record<string, unknown> {
    return {
      credential: result.credential,
      ...(result.secret === undefined ? {} : { secret: result.secret }),
      replayed: result.replayed,
    };
  }

  private credentialRotationResponse(result: {
    credential: CredentialDto;
    previousCredential: CredentialDto;
    secret: string | undefined;
    replayed: boolean;
  }): Record<string, unknown> {
    return {
      credential: result.credential,
      previousCredential: result.previousCredential,
      ...(result.secret === undefined ? {} : { secret: result.secret }),
      replayed: result.replayed,
    };
  }
}

export { OpenPlatformHttpController as OpenPlatformController };

function headerValue(
  headers: Record<string, unknown> | undefined,
  name: string,
): unknown {
  const entry = Object.entries(headers ?? {}).find(([key]) => key.toLowerCase() === name);
  const value = entry?.[1];
  return Array.isArray(value) ? value[0] : value;
}
