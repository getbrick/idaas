import type { DynamicModule, ModuleMetadata } from "@nestjs/common";
import { Module } from "@nestjs/common";
import { DEFAULT_ROLE_GRAPH, type RoleGraph } from "@getbrick/idaas-core";
import { GETBRICK_AUTH, GETBRICK_RBAC, type GetbrickAuthLike } from "./tokens.js";
import { GetbrickAuthMiddleware } from "./middleware.js";

@Module({})
export class GetbrickIdaasModule {
  static forRoot(input: { auth: GetbrickAuthLike; rbac?: RoleGraph }): DynamicModule {
    return {
      module: GetbrickIdaasModule,
      global: true,
      providers: [
        { provide: GETBRICK_AUTH, useValue: input.auth },
        { provide: GETBRICK_RBAC, useValue: input.rbac ?? DEFAULT_ROLE_GRAPH },
      ],
      exports: [GETBRICK_AUTH, GETBRICK_RBAC],
    };
  }

  configure(consumer: {
    apply(middleware: unknown): { forRoutes(...routes: string[]): unknown };
  }): void {
    consumer.apply(GetbrickAuthMiddleware).forRoutes("api/auth");
  }
}

export type GetbrickIdaasRootOptions = ModuleMetadata;
