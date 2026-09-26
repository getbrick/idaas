import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Inject,
  Optional,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseFilters,
  UseInterceptors,
} from "@nestjs/common";
import {
  CurrentUser,
  EffectivePermissions,
  GETBRICK_TRUST_PROXY,
  GetbrickPermissions,
} from "@getbrick/idaas-nestjs";
import { ApplicationEtagInterceptor, ControlPlaneExceptionFilter } from "./filter.js";
import {
  CONTROL_PLANE_BASE_PATH,
  type ControlPlaneActor,
} from "./types.js";
import { APPLICATION_PERMISSIONS, ApplicationService } from "./application-service.js";
import { parseApplicationWriteQuery } from "./application-validation.js";

@Controller(CONTROL_PLANE_BASE_PATH)
@UseFilters(ControlPlaneExceptionFilter)
@UseInterceptors(ApplicationEtagInterceptor)
export class ApplicationController {
  constructor(
    @Inject(ApplicationService) private readonly service: ApplicationService,
    @Optional() @Inject(GETBRICK_TRUST_PROXY) private readonly trustProxy = false,
  ) {}

  @Get("applications")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsRead)
  listApplications(
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listApplications(query, actor(user, permissions));
  }

  @Get("applications/:id")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsRead)
  getApplication(
    @Param("id") id: string,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.getApplication(id, actor(user, permissions));
  }

  @Post("applications")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsWrite)
  createApplication(
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.createApplication(body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Patch("applications/:id")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsWrite)
  updateApplication(
    @Param("id") id: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.updateApplication(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:id/enable")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsEnable)
  enableApplication(
    @Param("id") id: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.enableApplication(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:id/disable")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsDisable)
  disableApplication(
    @Param("id") id: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.disableApplication(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:id/archive")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsArchive)
  archiveApplication(
    @Param("id") id: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.archiveApplication(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:id/restore")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsRestore)
  restoreApplication(
    @Param("id") id: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.restoreApplication(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Delete("applications/:id/purge")
  @HttpCode(202)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsPurge)
  purgeApplication(
    @Param("id") id: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.purgeApplication(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:id/purge")
  @HttpCode(202)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsPurge)
  purgeApplicationPost(
    @Param("id") id: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.purgeApplication(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:id/validate")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsValidate)
  validateApplication(
    @Param("id") id: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.validateApplication(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Delete("applications/:id")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.applicationsArchive)
  deleteApplication(
    @Param("id") id: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.deleteApplication(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Get("applications/:applicationId/platforms")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsRead)
  listPlatforms(
    @Param("applicationId") applicationId: string,
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listPlatforms(applicationId, query, actor(user, permissions));
  }

  @Get("applications/:applicationId/platforms/:platformId")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsRead)
  getPlatform(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.getPlatform(applicationId, platformId, actor(user, permissions));
  }

  @Post("applications/:applicationId/platforms/:platformId/validate")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsValidate)
  validatePlatform(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.validatePlatform(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/platforms/:platformId/rotate-secret")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsRotateSecret)
  rotatePlatformSecret(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.rotatePlatformSecret(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/platforms/:platformId/revoke-secret")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsRevokeSecret)
  revokePlatformSecret(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.revokePlatformSecret(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/platforms")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsWrite)
  createPlatform(
    @Param("applicationId") applicationId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.createPlatform(applicationId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Patch("applications/:applicationId/platforms/:platformId")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsWrite)
  updatePlatform(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.updatePlatform(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/platforms/:platformId/enable")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsEnable)
  enablePlatform(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.enablePlatform(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/platforms/:platformId/disable")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsDisable)
  disablePlatform(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.disablePlatform(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/platforms/:platformId/archive")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsArchive)
  archivePlatform(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.archivePlatform(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/platforms/:platformId/restore")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsRestore)
  restorePlatform(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.restorePlatform(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Delete("applications/:applicationId/platforms/:platformId/purge")
  @HttpCode(202)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsPurge)
  purgePlatform(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.purgePlatform(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Delete("applications/:applicationId/platforms/:platformId")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.platformsArchive)
  deletePlatform(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.deletePlatform(applicationId, platformId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Get("applications/:applicationId/identities")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.externalIdentitiesRead)
  listExternalIdentities(
    @Param("applicationId") applicationId: string,
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listExternalIdentities(applicationId, query, actor(user, permissions));
  }

  @Get("applications/:applicationId/external-identities")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.externalIdentitiesRead)
  listApplicationExternalIdentities(
    @Param("applicationId") applicationId: string,
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listExternalIdentities(applicationId, query, actor(user, permissions));
  }

  @Get("applications/:applicationId/clients")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRead)
  listClients(
    @Param("applicationId") applicationId: string,
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listClients(applicationId, query, actor(user, permissions));
  }

  @Get("applications/:applicationId/oidc-clients")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRead)
  listOidcClients(
    @Param("applicationId") applicationId: string,
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listClients(applicationId, query, actor(user, permissions));
  }

  @Get("applications/:applicationId/clients/:clientId")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRead)
  getClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.getClient(applicationId, clientId, actor(user, permissions));
  }

  @Get("applications/:applicationId/oidc-clients/:clientId")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRead)
  getOidcClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.getClient(applicationId, clientId, actor(user, permissions));
  }

  @Post("applications/:applicationId/clients/:clientId/validate")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsValidate)
  validateClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.validateClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/clients/:clientId/rotate-secret")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRotateSecret)
  rotateClientSecret(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.rotateClientSecret(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/oidc-clients/:clientId/validate")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsValidate)
  validateOidcClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.validateClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/oidc-clients/:clientId/rotate-secret")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRotateSecret)
  rotateOidcClientSecret(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.rotateClientSecret(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/clients/:clientId/revoke-secret")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRevokeSecret)
  revokeClientSecret(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.revokeClientSecret(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/oidc-clients/:clientId/revoke-secret")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRevokeSecret)
  revokeOidcClientSecret(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.revokeClientSecret(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/clients")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsWrite)
  createClient(
    @Param("applicationId") applicationId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.createClient(applicationId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/oidc-clients")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsWrite)
  createOidcClient(
    @Param("applicationId") applicationId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.createClient(applicationId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Patch("applications/:applicationId/clients/:clientId")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsWrite)
  updateClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.updateClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Patch("applications/:applicationId/oidc-clients/:clientId")
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsWrite)
  updateOidcClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.updateClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/clients/:clientId/enable")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsEnable)
  enableClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.enableClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/clients/:clientId/disable")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsDisable)
  disableClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.disableClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/oidc-clients/:clientId/enable")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsEnable)
  enableOidcClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.enableClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/oidc-clients/:clientId/disable")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsDisable)
  disableOidcClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.disableClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/clients/:clientId/archive")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsArchive)
  archiveClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.archiveClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/clients/:clientId/restore")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRestore)
  restoreClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.restoreClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Delete("applications/:applicationId/clients/:clientId/purge")
  @HttpCode(202)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsPurge)
  purgeClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.purgeClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Delete("applications/:applicationId/clients/:clientId")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsArchive)
  deleteClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.deleteClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/oidc-clients/:clientId/archive")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsArchive)
  archiveOidcClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.archiveClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("applications/:applicationId/oidc-clients/:clientId/restore")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsRestore)
  restoreOidcClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.restoreClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Delete("applications/:applicationId/oidc-clients/:clientId/purge")
  @HttpCode(202)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsPurge)
  purgeOidcClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.purgeClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Delete("applications/:applicationId/oidc-clients/:clientId")
  @HttpCode(200)
  @GetbrickPermissions(APPLICATION_PERMISSIONS.clientsArchive)
  deleteOidcClient(
    @Param("applicationId") applicationId: string,
    @Param("clientId") clientId: string,
    @Body() body: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ApplicationControllerRequest,
  ) {
    return this.service.deleteClient(applicationId, clientId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }
}

export interface ApplicationControllerRequest {
  headers?: Record<string, unknown>;
  id?: unknown;
  ip?: unknown;
  ips?: unknown;
  query?: unknown;
}

export { ApplicationController as ApplicationManagementController };

function actor(
  user: Record<string, unknown> | undefined,
  permissions: string[],
): ControlPlaneActor {
  return {
    user,
    permissions,
    roles: rolesFromUser(user),
  };
}

function requestContext(
  request: ApplicationControllerRequest = {},
  trustProxy = false,
): {
  requestId?: string;
  ipAddress?: string;
  userAgent?: string;
  ifMatch?: string;
  idempotencyKey?: string;
} {
  parseApplicationWriteQuery(request.query);
  const headers = request.headers ?? {};
  const userAgent = headerValue(headers, "user-agent");
  const forwarded = trustProxy ? headerValue(headers, "x-forwarded-for") : undefined;
  const ip = forwarded?.split(",")[0]?.trim() ?? textValue(request.ip) ?? (trustProxy
    ? textValue(Array.isArray(request.ips) ? request.ips[0] : undefined)
    : undefined);
  const requestId = requestIdFromHeaders(request);
  const ifMatch = headerValue(headers, "if-match");
  const idempotencyKey = headerValue(headers, "idempotency-key");
  return {
    ...(requestId === undefined ? {} : { requestId }),
    ...(ip === undefined ? {} : { ipAddress: ip }),
    ...(userAgent === undefined ? {} : { userAgent }),
    ...(ifMatch === undefined ? {} : { ifMatch }),
    ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
  };
}

function requestIdFromHeaders(request: ApplicationControllerRequest): string | undefined {
  const headers = request.headers ?? {};
  const values = [headers["x-request-id"], headers["x-correlation-id"], request.id];
  for (const value of values) {
    if (typeof value !== "string") continue;
    const normalized = value.trim();
    if (normalized.length === 0 || normalized.length > 128 || /[\u0000-\u001f\u007f]/u.test(normalized) || /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)) continue;
    return normalized;
  }
  return undefined;
}

function headerValue(headers: Record<string, unknown>, name: string): string | undefined {
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name);
  const value = Array.isArray(entry?.[1]) ? entry?.[1][0] : entry?.[1];
  return textValue(value);
}

function textValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 512 && !/[\u0000-\u001f\u007f]/u.test(normalized)
    ? normalized
    : undefined;
}

function rolesFromUser(user: Record<string, unknown> | undefined): string[] {
  if (!user) return [];
  const values = [
    ...(Array.isArray(user.roles) ? user.roles : []),
    ...(Array.isArray(user.role) ? user.role : typeof user.role === "string" ? [user.role] : []),
  ];
  return [...new Set(values.filter((value): value is string => typeof value === "string"))];
}
