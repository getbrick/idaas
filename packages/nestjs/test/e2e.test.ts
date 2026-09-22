import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { Test } from "@nestjs/testing";
import { Controller, Get, Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import request from "supertest";
import express from "express";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createIdaas, buildTableMap } from "@getbrick/idaas-core";
import {
  GetbrickIdaasModule,
  GetbrickAuthGuard,
  CurrentUser,
} from "../src/index.js";

@Controller("me")
class MeController {
  @Get()
  me(@CurrentUser() user: Record<string, unknown> | undefined) {
    return { email: user?.email };
  }
}

@Module({
  imports: [GetbrickIdaasModule.forRoot({ auth: createAuth() })],
  controllers: [MeController],
  providers: [{ provide: APP_GUARD, useClass: GetbrickAuthGuard }],
})
class AppModule {}

function createAuth() {
  const tables = buildTableMap();
  const data: Record<string, unknown[]> = {};
  for (const name of Object.values(tables)) data[name] = [];
  return createIdaas({ config: { appName: "E2E" }, database: memoryAdapter(data) });
}

describe("nestjs adapter e2e", () => {
  it("signs up via proxied handler and protects routes", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    const app = moduleRef.createNestApplication();
    app.use(express.json());
    await app.init();

    const server = app.getHttpServer();

    const signUp = await request(server)
      .post("/api/auth/sign-up/email")
      .send({ email: "u@example.com", password: "supersecret123", name: "U" });
    expect(signUp.status).toBe(200);

    const cookies = ((signUp.headers["set-cookie"] ?? []) as unknown as string[])
      .map((c) => c.split(";")[0])
      .join("; ");
    expect(cookies).toBeTruthy();

    const meUnauthed = await request(server).get("/me");
    expect(meUnauthed.status).toBe(401);

    const meAuthed = await request(server)
      .get("/me")
      .set("Cookie", cookies);
    expect(meAuthed.status).toBe(200);
    expect(meAuthed.body.email).toBe("u@example.com");

    await app.close();
  });
});
