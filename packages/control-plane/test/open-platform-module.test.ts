import "reflect-metadata";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  createDevelopmentOpenPlatformAuthorization,
  createOpenPlatformRequestContextIssuer,
  OPEN_PLATFORM_HTTP_BASE_PATH,
  OpenPlatformModule,
  type OpenPlatformHttpRequest,
} from "../src/open-platform/index.js";
import {
  CommerceDomainService,
  InMemoryCommerceRepositories,
} from "../src/open-platform/commerce/index.js";

const now = new Date("2030-03-01T00:00:00.000Z");
const tenantId = "tenant-composite";
const actorId = "actor-composite";

function authenticated<T extends { set: (name: string, value: string) => T }>(value: T): T {
  return value.set("x-composite-auth", "valid");
}

describe("open platform composite module", () => {
  it("registers the core and commerce HTTP surfaces together", async () => {
    const issuer = createOpenPlatformRequestContextIssuer({
      issuerId: "open-platform-composite-tests",
      attestation: Object.freeze({ test: true }),
      clock: () => now,
    });
    const resolver = {
      resolve: (httpRequest: OpenPlatformHttpRequest) => {
        const headers = httpRequest.headers ?? {};
        const authenticatedRequest = Object.entries(headers).some(
          ([key, value]) => key.toLowerCase() === "x-composite-auth" && value === "valid",
        );
        return authenticatedRequest
          ? { tenantId, actorId, requestId: "composite-request" }
          : undefined;
      },
    };
    const commerce = new CommerceDomainService({
      repositories: new InMemoryCommerceRepositories(),
      clock: () => now,
    });
    const moduleRef = await Test.createTestingModule({
      imports: [
        OpenPlatformModule.forRoot({
          platform: {
            mode: "test",
            authorization: createDevelopmentOpenPlatformAuthorization("all"),
            contextIssuer: issuer,
            clock: () => now,
            resolver,
          },
          commerce: {
            service: commerce,
            mode: "test",
            contextIssuer: issuer,
            resolver,
          },
        }),
      ],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();

    const tenants = await authenticated(request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`));
    expect(tenants.status).toBe(200);
    expect(tenants.body).toEqual([]);

    const listings = await authenticated(request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/marketplace/listings`));
    expect(listings.status).toBe(200);
    expect(listings.body).toMatchObject({ items: [], hasMore: false });

    await app.close();
  });
});
