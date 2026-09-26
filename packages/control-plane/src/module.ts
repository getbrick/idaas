import {
  Inject,
  Injectable,
  Module,
  Optional,
  type DynamicModule,
  type OnModuleInit,
  type Provider,
} from "@nestjs/common";
import type { IdaasProfile, RoleGraph } from "@getbrick/idaas-core";
import {
  GetbrickIdaasModule,
  type GetbrickAuthLike,
  type GetbrickGuardMode,
} from "@getbrick/idaas-nestjs";
import { ControlPlaneController } from "./controller.js";
import { InMemoryControlPlaneRepository } from "./repository.js";
import { ControlPlaneService } from "./service.js";
import type {
  ControlPlaneRepository,
  ControlPlaneServiceOptions,
} from "./types.js";

export const CONTROL_PLANE_REPOSITORY = "CONTROL_PLANE_REPOSITORY";
export const CONTROL_PLANE_READINESS = "CONTROL_PLANE_READINESS";

export interface ControlPlaneModuleOptions {
  auth: GetbrickAuthLike;
  repository?: ControlPlaneRepository;
  rbac?: RoleGraph;
  guard?: GetbrickGuardMode;
  basePath?: string;
  trustProxy?: boolean;
  profile?: IdaasProfile;
  readiness?: () => boolean | Promise<boolean>;
  service?: ControlPlaneServiceOptions;
}

@Injectable()
class ControlPlaneReadiness implements OnModuleInit {
  constructor(
    @Optional()
    @Inject(CONTROL_PLANE_READINESS)
    private readonly check?: () => boolean | Promise<boolean>,
  ) {}

  async onModuleInit(): Promise<void> {
    if (typeof this.check !== "function") return;
    if (!(await this.check())) {
      throw new Error("[getbrick-idaas] control-plane storage is not ready");
    }
  }
}

@Module({
  controllers: [ControlPlaneController],
  providers: [
    {
      provide: CONTROL_PLANE_REPOSITORY,
      useFactory: () => new InMemoryControlPlaneRepository(),
    },
    {
      provide: ControlPlaneService,
      useFactory: (repository: ControlPlaneRepository) => new ControlPlaneService(repository),
      inject: [CONTROL_PLANE_REPOSITORY],
    },
  ],
  exports: [CONTROL_PLANE_REPOSITORY, ControlPlaneService],
})
export class ControlPlaneModule {
  static forRoot(options: ControlPlaneModuleOptions): DynamicModule {
    if (options.profile === "production" && !options.auth) {
      throw new Error("[getbrick-idaas] production control plane requires authentication");
    }
    const suppliedRepository = options.repository;
    if (options.profile === "production" && !suppliedRepository) {
      throw new Error("[getbrick-idaas] production control plane requires a persistent repository");
    }
    if (options.profile === "production" && suppliedRepository instanceof InMemoryControlPlaneRepository) {
      throw new Error("[getbrick-idaas] production control plane cannot use an in-memory repository");
    }
    const repository = suppliedRepository ?? new InMemoryControlPlaneRepository();
    const readiness = options.readiness ?? repository.isReady?.bind(repository);
    if (options.profile === "production" && !readiness) {
      throw new Error("[getbrick-idaas] production control plane requires a storage readiness check");
    }
    const serviceOptions: ControlPlaneServiceOptions = {
      ...options.service,
      readiness: options.service?.readiness ?? readiness,
    };
    const providers: Provider[] = [
      { provide: CONTROL_PLANE_REPOSITORY, useValue: repository },
      {
        provide: ControlPlaneService,
        useFactory: (value: ControlPlaneRepository) => new ControlPlaneService(value, serviceOptions),
        inject: [CONTROL_PLANE_REPOSITORY],
      },
    ];
    if (readiness) {
      providers.push(
        { provide: CONTROL_PLANE_READINESS, useValue: readiness },
        ControlPlaneReadiness,
      );
    }
    return {
      module: ControlPlaneModule,
      imports: [
        GetbrickIdaasModule.forRoot({
          auth: options.auth,
          rbac: options.rbac,
          guard: options.guard,
          basePath: options.basePath,
          trustProxy: options.trustProxy,
        }),
      ],
      controllers: [ControlPlaneController],
      providers,
      exports: [CONTROL_PLANE_REPOSITORY, ControlPlaneService],
    };
  }
}
