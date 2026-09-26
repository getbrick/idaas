import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { Test } from "@nestjs/testing";
import request from "supertest";
import {
  APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS,
  APPLICATION_MANAGEMENT_PERMISSIONS,
  APPLICATION_TYPES,
  DEFAULT_APPLICATION_CLIENT_AUTH_METHOD,
} from "@getbrick/idaas-contracts";
import {
  toApplicationClientSummary,
  toApplicationExternalIdentitySummary,
  toApplicationSummary,
} from "../src/application-dto.js";
import {
  parseApplicationClientCreateRequest,
  parseApplicationCreateRequest,
  parseApplicationLifecycleActionRequest,
  validateApplicationClientIdUniqueness,
} from "../src/application-validation.js";
import { InMemoryApplicationRepository } from "../src/application-repository.js";
import { ApplicationController } from "../src/application-controller.js";
import { ApplicationService } from "../src/application-service.js";

function actor(permissions: string[]) {
  return { user: { id: "actor-1" }, permissions };
}

function allActor() {
  return actor([
    ...Object.values(APPLICATION_MANAGEMENT_PERMISSIONS),
    "applications:enable",
    "applications:disable",
    "application-platforms:enable",
    "application-platforms:disable",
    "application-platforms:archive",
    "application-platforms:restore",
    "application-platforms:purge",
    "application-platforms:revoke-secret",
    "application-clients:enable",
    "application-clients:disable",
    "application-clients:archive",
    "application-clients:restore",
    "application-clients:purge",
    "application-clients:revoke-secret",
  ]);
}

describe("application-management contract slice", () => {
  it("keeps application type and private_key_jwt input strict", () => {
    expect(APPLICATION_MANAGEMENT_PERMISSIONS.applicationsArchive).toBe("applications:archive");
    expect(APPLICATION_MANAGEMENT_PERMISSIONS.applicationsRestore).toBe("applications:restore");
    expect(APPLICATION_MANAGEMENT_PERMISSIONS.applicationsPurge).toBe("applications:purge");
    expect(APPLICATION_MANAGEMENT_PERMISSIONS.clientsRevokeSecret).toBe("application-clients:revoke-secret");
    expect(APPLICATION_TYPES).toEqual(["web", "native"]);
    expect(parseApplicationCreateRequest({ name: "Native", slug: "native", applicationType: "native" })).toMatchObject({
      applicationType: "native",
    });
    expect(() => parseApplicationCreateRequest({ name: "Bad", slug: "bad", applicationType: "mobile" })).toThrow();
    expect(() => parseApplicationCreateRequest({ name: "Bad", slug: "bad", unsupported: true })).toThrow();

    const nativeRedirect = parseApplicationClientCreateRequest({
      clientId: "native-public",
      redirectUris: ["com.example.app:/oauth/callback"],
      tokenEndpointAuthMethod: "none",
    }, { applicationType: "native" });
    expect(nativeRedirect.redirectUris).toEqual(["com.example.app:/oauth/callback"]);
    expect(() => parseApplicationClientCreateRequest({
      clientId: "web-public",
      redirectUris: ["com.example.app:/oauth/callback"],
      tokenEndpointAuthMethod: "none",
    })).toThrow();

    const privateKeyJwt = parseApplicationClientCreateRequest({
      clientId: "native-client",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "private_key_jwt",
      tokenEndpointAuthSigningAlg: "ES256",
      jwksUri: "https://client.example.test/jwks.json",
      keyId: "key-1",
      privateKeyRef: "vault://clients/native-client/key",
    });
    expect(privateKeyJwt).toMatchObject({ tokenEndpointAuthMethod: "private_key_jwt", tokenEndpointAuthSigningAlg: "ES256" });
    expect(parseApplicationClientCreateRequest({
      clientId: "native-client-default-alg",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "private_key_jwt",
      jwksUri: "https://client.example.test/jwks.json",
    })).toMatchObject({ tokenEndpointAuthSigningAlg: "RS256" });
    expect(() => parseApplicationClientCreateRequest({
      clientId: "native-client-2",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "private_key_jwt",
      tokenEndpointAuthSigningAlg: "ES256",
    })).toThrow();
    expect(() => parseApplicationClientCreateRequest({
      clientId: "native-client-3",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "private_key_jwt",
      tokenEndpointAuthSigningAlg: "ES256",
      privateKey: "raw-private-key",
    })).toThrow();
    expect(() => parseApplicationLifecycleActionRequest({ unexpected: true })).toThrow();
  });

  it("keeps four algorithms, explicit shared auth and native policy aligned", () => {
    expect(APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS).toEqual(["RS256", "PS256", "ES256", "EdDSA"]);
    expect(DEFAULT_APPLICATION_CLIENT_AUTH_METHOD).toBe("private_key_jwt");
    for (const algorithm of APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS) {
      expect(parseApplicationClientCreateRequest({
        clientId: `client-${algorithm}`,
        redirectUris: ["https://client.example.test/callback"],
        tokenEndpointAuthMethod: "private_key_jwt",
        tokenEndpointAuthSigningAlg: algorithm,
        jwksUri: "https://client.example.test/jwks.json",
      })).toMatchObject({ tokenEndpointAuthSigningAlg: algorithm });
    }
    expect(parseApplicationClientCreateRequest({
      clientId: "default-confidential",
      redirectUris: ["https://client.example.test/callback"],
      privateKeyRef: "vault://clients/default-confidential",
    })).toMatchObject({ tokenEndpointAuthMethod: "private_key_jwt", tokenEndpointAuthSigningAlg: "RS256" });
    expect(() => parseApplicationClientCreateRequest({
      clientId: "implicit-shared",
      redirectUris: ["https://client.example.test/callback"],
      secretRef: "vault://clients/implicit-shared",
    })).toThrow();
    expect(parseApplicationClientCreateRequest({
      clientId: "explicit-shared",
      clientIdScope: "global",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "client_secret_post",
      secretRef: "vault://clients/explicit-shared",
    })).toMatchObject({ clientIdScope: "global", tokenEndpointAuthMethod: "client_secret_post" });
    expect(() => parseApplicationClientCreateRequest({
      clientId: "bad-scope",
      clientIdScope: "tenant" as never,
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "client_secret_post",
      secretRef: "vault://clients/bad-scope",
    })).toThrow();
    expect(() => validateApplicationClientIdUniqueness([
      { clientId: "shared-client" },
      { clientId: "SHARED-CLIENT" },
    ])).toThrow(/globally unique/i);
    expect(() => parseApplicationClientCreateRequest({
      clientId: "native-private-key",
      applicationType: "native",
      redirectUris: ["com.example.app:/oauth/callback"],
      tokenEndpointAuthMethod: "private_key_jwt",
      privateKeyRef: "vault://clients/native-private-key",
    })).toThrow();
    expect(() => parseApplicationClientCreateRequest({
      clientId: "native-no-pkce",
      applicationType: "native",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "none",
      requirePkce: false,
    })).toThrow();
  });

  it("masks credential references while exposing readiness, versions and effective status", () => {
    const dto = toApplicationSummary({
      id: "app-1",
      name: "Example",
      slug: "example",
      applicationType: "native",
      status: "active",
      readiness: { status: "ready", ready: true },
      version: 7,
      etag: "app-1:7",
      secretRef: "vault://app-secret",
      rawCredential: "do-not-expose",
    });
    expect(dto).toMatchObject({
      applicationType: "native",
      readiness: { status: "ready", ready: true },
      effectiveStatus: "active",
      version: 7,
      etag: "app-1:7",
    });
    expect(dto).not.toHaveProperty("secretRef");
    expect(dto).not.toHaveProperty("rawCredential");
    expect(JSON.stringify(dto)).not.toContain("vault://app-secret");

    const identity = toApplicationExternalIdentitySummary({
      id: "identity-1",
      applicationId: "app-1",
      provider: "wechat",
      subject: "subject-1",
      openid: "openid-1",
      accessToken: "raw-access-token",
    });
    expect(identity).toMatchObject({ provider: "wechat", subject: "subject-1", openid: "openid-1" });
    expect(identity).not.toHaveProperty("accessToken");

    const privateClient = toApplicationClientSummary({
      id: "client-1",
      applicationId: "app-1",
      clientId: "private-client",
      status: "active",
      redirectUris: [],
      postLogoutRedirectUris: [],
      grantTypes: ["authorization_code"],
      responseTypes: ["code"],
      scopes: ["openid"],
      tokenEndpointAuthMethod: "private_key_jwt",
      privateKeyRef: "vault://clients/private-client",
      rawPrivateKey: "do-not-expose",
    });
    expect(privateClient).toMatchObject({ tokenEndpointAuthMethod: "private_key_jwt", tokenEndpointAuthSigningAlg: "RS256", hasSecret: false });
    expect(privateClient).not.toHaveProperty("privateKeyRef");
    expect(privateClient).not.toHaveProperty("rawPrivateKey");
  });

  it("supports lifecycle, validation and secret rotation without returning secret material", async () => {
    const repository = new InMemoryApplicationRepository();
    const service = new ApplicationService(repository);
    const application = await service.createApplication({ name: "Lifecycle", slug: "lifecycle", applicationType: "native" }, allActor());
    expect(application).toMatchObject({ applicationType: "native", status: "active", version: 1 });

    const nativeClient = await service.createClient(application.id, {
      clientId: "native-public-client",
      redirectUris: ["com.example.app:/oauth/callback"],
      tokenEndpointAuthMethod: "none",
      scopes: ["openid"],
    }, allActor());
    expect(nativeClient.redirectUris).toEqual(["com.example.app:/oauth/callback"]);
    const validation = await service.validateApplication(application.id, {}, allActor());
    expect(validation).toMatchObject({ applicationId: application.id, valid: true, status: "valid" });
     const lifecycleApplication = await service.createApplication({ name: "LifecycleOnly", slug: "lifecycle-only" }, allActor());
     const archived = await service.archiveApplication(lifecycleApplication.id, { expectedVersion: lifecycleApplication.version }, allActor());
    expect(archived).toMatchObject({ status: "archived", lifecycleStatus: "archived", effectiveStatus: "archived" });
     const restored = await service.restoreApplication(lifecycleApplication.id, { expectedVersion: archived.version }, allActor());
    expect(restored).toMatchObject({ status: "active", lifecycleStatus: "active" });

    const client = await service.createClient(application.id, {
      clientId: "confidential-client",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "client_secret_basic",
      secretRef: "vault://clients/confidential-client/one",
    }, allActor());
    const rotated = await service.rotateClientSecret(application.id, client.id, {
      expectedVersion: client.version,
      secretRef: "vault://clients/confidential-client/two",
    }, allActor());
    expect(rotated).toMatchObject({ secretStatus: "configured", secretVersion: 2 });
    expect(rotated).not.toHaveProperty("secretRef");
    expect(JSON.stringify(rotated)).not.toContain("vault://clients/confidential-client");

     const archivedAgain = await service.archiveApplication(lifecycleApplication.id, {}, allActor());
     const purged = await service.purgeApplication(lifecycleApplication.id, { expectedVersion: archivedAgain.version }, allActor());
     expect(purged).toMatchObject({ applicationId: lifecycleApplication.id, operation: "purge", status: "queued" });
  });

  it("registers lifecycle and validation routes", async () => {
    const repository = new InMemoryApplicationRepository({
       applications: [
         { id: "app-1", name: "Example", slug: "example", status: "active" },
         { id: "app-2", name: "Identities", slug: "identities", status: "active" },
       ],
       externalIdentities: [{ id: "identity-1", applicationId: "app-2", provider: "wechat", subject: "subject-1" }],
    });
    const service = new ApplicationService(repository, { requireActor: false });
    const moduleRef = await Test.createTestingModule({
      controllers: [ApplicationController],
      providers: [{ provide: ApplicationService, useValue: service }],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();
     const archived = await request(server).post("/api/idaas/v1/applications/app-1/archive").send({});
     expect(archived.status).toBe(200);
     expect(archived.body).toMatchObject({ status: "archived" });
     const restored = await request(server).post("/api/idaas/v1/applications/app-1/restore").send({});
     expect(restored.status).toBe(200);
     expect(restored.body).toMatchObject({ status: "active" });
     const validated = await request(server).post("/api/idaas/v1/applications/app-1/validate").send({});
     expect(validated.status).toBe(200);
     expect(validated.body).toMatchObject({ applicationId: "app-1", status: "valid" });
     const identities = await request(server).get("/api/idaas/v1/applications/app-2/identities");
     expect(identities.status).toBe(200);
     expect(identities.body.items[0]).toMatchObject({ id: "identity-1", provider: "wechat" });
     const archivedAgain = await request(server).post("/api/idaas/v1/applications/app-1/archive").send({});
     expect(archivedAgain.status).toBe(200);
     const purged = await request(server).post("/api/idaas/v1/applications/app-1/purge").send({});
     expect(purged.status).toBe(202);
     expect(purged.body).toMatchObject({ applicationId: "app-1", operation: "purge", status: "queued" });
    await app.close();
  });

  it("requires the explicit lifecycle and rotation permissions", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Example", slug: "example", status: "active" }],
    });
    const service = new ApplicationService(repository);
    await expect(service.archiveApplication("app-1", {}, actor(["applications:write"]))).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(service.validateApplication("app-1", {}, actor(["applications:read"]))).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});
