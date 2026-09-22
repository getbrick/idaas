import type { DynamicModule, ModuleMetadata } from "@nestjs/common";
import { Module } from "@nestjs/common";
import { GETBRICK_AUTH, type GetbrickAuthLike } from "./tokens.js";
import { GetbrickAuthMiddleware } from "./middleware.js";

@Module({})
export class GetbrickIdaasModule {
  static forRoot(input: { auth: GetbrickAuthLike }): DynamicModule {
    return {
      module: GetbrickIdaasModule,
      global: true,
      providers: [
        { provide: GETBRICK_AUTH, useValue: input.auth },
      ],
      exports: [GETBRICK_AUTH],
    };
  }

  configure(consumer: {
    apply(middleware: unknown): { forRoutes(...routes: string[]): unknown };
  }): void {
    consumer.apply(GetbrickAuthMiddleware).forRoutes("api/auth");
  }
}

export type GetbrickIdaasRootOptions = ModuleMetadata;
