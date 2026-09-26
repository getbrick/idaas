import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { Test } from "@nestjs/testing";
import request from "supertest";
import {
  InMemoryApplicationRepository,
  toApplicationClientSummary,
  toApplicationPlatformSummary,
  toApplicationSummary,
} from "../src/index.js";
import { ApplicationService } from "../src/application-service.js";
import { ApplicationController } from "../src/application-controller.js";
import { InMemorySecretBindingRepository } from "../src/secret-binding.js";

function actor() {
  return { user: { id: "security-actor" }, permissions: ["*:*"] };
}

describe("application management security boundaries", () => {
  it("applies projected readiness filters before pagination", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [
        { id: "ready-app", name: "Ready", slug: "ready", status: "active" },
        { id: "not-ready-app", name: "Disabled", slug: "disabled", status: "disabled" },
        { id: "not-ready-app-2", name: "Missing", slug: "missing", status: "disabled" },
      ],
    });
    const service = new ApplicationService(repository);
    const page = await service.listApplications({ readiness: "not_ready", limit: 1 }, actor());
    expect(page.items).toHaveLength(1);
    expect(page.total).toBe(2);
    expect(page.hasMore).toBe(true);
    expect(page.nextCursor).toBeTruthy();
  });

  it("accepts role-based authorization from user role values", async () => {
    const service = new ApplicationService(new InMemoryApplicationRepository());
    await expect(service.listApplications({}, { user: { id: "role-admin", role: " ADMIN " } })).resolves.toBeDefined();
    await expect(service.listApplications({}, { user: { id: "role-user", role: "user" } })).rejects.toMatchObject({ statusCode: 403 });
  });

  it("keeps secret references and client identity out of ordinary patches", async () => {
    const repository = new InMemoryApplicationRepository();
    const service = new ApplicationService(repository);
    const application = await service.createApplication({ name: "Security", slug: "security" }, actor());
    const platform = await service.createPlatform(application.id, {
      type: "web",
      redirectUris: ["https://client.example.test/callback"],
      secretRef: "vault://platform/one",
    }, actor());
    const client = await service.createClient(application.id, {
      clientId: "security-client",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "client_secret_basic",
      secretRef: "vault://client/one",
    }, actor());

    await expect(service.updatePlatform(application.id, platform.id, { secretRef: "vault://platform/two" }, actor())).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    await expect(service.updateClient(application.id, client.id, { secretRef: "vault://client/two" }, actor())).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    await expect(service.updateClient(application.id, client.id, { privateKeyRef: "vault://client/key" }, actor())).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    await expect(service.updateClient(application.id, client.id, { clientId: "renamed-client" }, actor())).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    expect((await service.getPlatform(application.id, platform.id, actor())).secretStatus).toBe("configured");
    expect((await service.getClient(application.id, client.id, actor())).clientId).toBe("security-client");
  });

  it("requires an optimistic lock for rotation and accepts If-Match", async () => {
    const repository = new InMemoryApplicationRepository();
    const service = new ApplicationService(repository);
    const application = await service.createApplication({ name: "Locks", slug: "locks" }, actor());
    const client = await service.createClient(application.id, {
      clientId: "locked-client",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "client_secret_basic",
      secretRef: "vault://client/one",
    }, actor());

    await expect(service.rotateClientSecret(application.id, client.id, { secretRef: "vault://client/two" }, actor())).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    const rotated = await service.rotateClientSecret(
      application.id,
      client.id,
      { secretRef: "vault://client/two" },
      actor(),
      { ifMatch: `"application-client:${client.id}:${client.version}"` },
    );
    expect(rotated.secretVersion).toBe(2);
    await expect(service.rotateClientSecret(application.id, client.id, { secretRef: "vault://client/three", expectedVersion: client.version }, actor())).rejects.toMatchObject({ code: "CONFLICT" });
    const revoked = await service.revokeClientSecret(application.id, client.id, { expectedVersion: rotated.version }, actor());
    expect(revoked).toMatchObject({ hasSecret: false, secretStatus: "revoked", readiness: "not_ready" });
    expect(JSON.stringify(revoked)).not.toContain("vault://client");
  });

  it("queues an idempotent purge job instead of deleting", async () => {
    const repository = new InMemoryApplicationRepository();
    const service = new ApplicationService(repository);
    const application = await service.createApplication({ name: "Purge", slug: "purge" }, actor());
    const archived = await service.archiveApplication(application.id, {}, actor());
    const first = await service.purgeApplication(application.id, { idempotencyKey: "purge-1" }, actor());
    const second = await service.purgeApplication(application.id, { idempotencyKey: "purge-1" }, actor());
    expect(first).toMatchObject({ applicationId: application.id, operation: "purge", status: "queued" });
    expect(second.id).toBe(first.id);
    expect((await service.getApplication(application.id, actor())).status).toBe("archived");
    expect(archived.status).toBe("archived");
  });

  it("cascades lifecycle changes atomically and projects archived child status", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Lifecycle", slug: "lifecycle", status: "active" }],
      platforms: [{ id: "platform-1", applicationId: "app-1", type: "web", status: "active" }],
      clients: [{ id: "client-1", applicationId: "app-1", clientId: "client-1", status: "active", tokenEndpointAuthMethod: "none" }],
    });
    const service = new ApplicationService(repository);

    const archived = await service.archiveApplication("app-1", {}, actor());
    expect(archived).toMatchObject({ status: "archived", lifecycleStatus: "archived" });
    expect((await service.listPlatforms("app-1", { status: "archived" }, actor())).items[0]).toMatchObject({ status: "archived" });
    expect((await service.listClients("app-1", { status: "archived" }, actor())).items[0]).toMatchObject({ status: "archived" });

    const restored = await service.restoreApplication("app-1", { expectedVersion: archived.version }, actor());
    expect(restored).toMatchObject({ status: "active", lifecycleStatus: "active" });
    expect((await service.listPlatforms("app-1", { status: "active" }, actor())).items[0]).toMatchObject({ status: "active" });
    expect((await service.listClients("app-1", { status: "active" }, actor())).items[0]).toMatchObject({ status: "active" });
  });

  it("does not promote stale readiness when credentials are unavailable", () => {
    expect(toApplicationPlatformSummary({
      id: "platform-1",
      applicationId: "app-1",
      type: "web",
      status: "active",
      readiness: "ready",
      credentialConfigured: false,
    })).toMatchObject({ readiness: "not_ready", effectiveStatus: "not_ready" });
    expect(toApplicationClientSummary({
      id: "client-1",
      applicationId: "app-1",
      clientId: "client-1",
      status: "active",
      tokenEndpointAuthMethod: "client_secret_basic",
      hasSecret: false,
      readiness: "ready",
    })).toMatchObject({ readiness: "not_ready", effectiveStatus: "not_ready" });
  });

  it("compensates a created resource when secret binding persistence fails", async () => {
    const repository = new InMemoryApplicationRepository();
    const bindings = new InMemorySecretBindingRepository();
    bindings.create = async () => {
      throw new Error("binding unavailable");
    };
    const service = new ApplicationService(repository, { secretBindings: bindings });
    const application = await service.createApplication({ name: "Atomic", slug: "atomic" }, actor());
    await expect(service.createClient(application.id, {
      clientId: "atomic-client",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "client_secret_basic",
      secretRef: "vault://client/atomic",
    }, actor())).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    expect((await service.listClients(application.id, {}, actor())).items).toHaveLength(0);
  });

  it("blocks application type changes when children exceed one page", async () => {
    const platforms = Array.from({ length: 101 }, (_, index) => ({
      id: `platform-${index}`,
      applicationId: "app-1",
      type: "web",
      status: "active",
      redirectUris: [],
      credentialConfigured: true,
      secretRef: "vault://platform",
    }));
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Children", slug: "children", applicationType: "web" }],
      platforms,
    });
    const service = new ApplicationService(repository);
    await expect(service.updateApplication("app-1", { applicationType: "native" }, actor())).rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("does not expose PUT aliases and returns an accepted purge job", async () => {
    const repository = new InMemoryApplicationRepository();
    const service = new ApplicationService(repository, { requireActor: false });
    const moduleRef = await Test.createTestingModule({
      controllers: [ApplicationController],
      providers: [{ provide: ApplicationService, useValue: service }],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const application = await service.createApplication({ name: "Routes", slug: "routes" });
    const server = app.getHttpServer();
    const put = await request(server).put(`/api/idaas/v1/applications/${application.id}`).send({ name: "No PUT" });
    expect(put.status).toBe(404);
    const archived = await request(server).delete(`/api/idaas/v1/applications/${application.id}`).send({});
     expect(archived.status).toBe(200);
     expect(archived.body.status).toBe("archived");
     expect(archived.headers.etag).toBe(`"${archived.body.etag}"`);
    const purge = await request(server).post(`/api/idaas/v1/applications/${application.id}/purge`).send({});
    expect(purge.status).toBe(202);
    expect(purge.body).toMatchObject({ operation: "purge", status: "queued" });
    await app.close();
  });

  it("derives effective status instead of trusting stale repository fields", () => {
    expect(toApplicationSummary({
      id: "app-1",
      name: "Example",
      slug: "example",
      status: "active",
      lifecycleStatus: "archived",
      effectiveStatus: "active",
    }).effectiveStatus).toBe("archived");
    expect(toApplicationSummary({
      id: "app-1",
      name: "Example",
      slug: "example",
      status: "active",
      readiness: "not_ready",
      effectiveStatus: "active",
    }).effectiveStatus).toBe("not_ready");
    expect(toApplicationClientSummary({
      id: "client-1",
      applicationId: "app-1",
      clientId: "client",
      status: "active",
      redirectUris: [],
      postLogoutRedirectUris: [],
      grantTypes: ["authorization_code"],
      responseTypes: ["code"],
      scopes: ["openid"],
      tokenEndpointAuthMethod: "client_secret_basic",
      hasSecret: true,
      readiness: "ready",
      effectiveStatus: "active",
    }).effectiveStatus).toBe("active");
  });
});
