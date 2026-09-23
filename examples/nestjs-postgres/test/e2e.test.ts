import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { Test } from "@nestjs/testing";
import { Controller, Get, Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import request from "supertest";
import express from "express";
import { GetbrickIdaasModule, GetbrickAuthGuard, CurrentUser } from "@getbrick/idaas-nestjs";
import { auth } from "../src/auth.js";
import { pool } from "../src/auth.js";

@Controller("me")
class MeController {
  @Get()
  me(@CurrentUser() user: Record<string, unknown> | undefined) {
    return { email: user?.email };
  }
}

@Module({
  imports: [GetbrickIdaasModule.forRoot({ auth })],
  controllers: [MeController],
  providers: [{ provide: APP_GUARD, useClass: GetbrickAuthGuard }],
})
class ExampleAppModule {}

describe("nestjs-postgres example e2e", () => {
  it("signs up against real postgres and protects routes", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ExampleAppModule],
    }).compile();
    const app = moduleRef.createNestApplication();
    app.use(express.json());
    await app.init();

    const server = app.getHttpServer();
    const email = `e2e-${Date.now()}@example.com`;

    const signUp = await request(server)
      .post("/api/auth/sign-up/email")
      .send({ email, password: "supersecret123", name: "E2E" });
    expect(signUp.status).toBe(200);

    const cookies = ((signUp.headers["set-cookie"] ?? []) as unknown as string[])
      .map((c) => c.split(";")[0])
      .join("; ");
    expect(cookies).toBeTruthy();

    const meAuthed = await request(server).get("/me").set("Cookie", cookies);
    expect(meAuthed.status).toBe(200);
    expect(meAuthed.body.email).toBe(email);

    const meUnauthed = await request(server).get("/me");
    expect(meUnauthed.status).toBe(401);

    await app.close();
  });
});
