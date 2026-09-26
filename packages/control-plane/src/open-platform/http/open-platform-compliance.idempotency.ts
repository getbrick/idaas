import { Inject, Injectable } from "@nestjs/common";
import {
  assertComplianceIdempotencyAvailable,
  assertComplianceIdempotencyReplayable,
  complianceIdempotencyStorageUnavailable,
  createComplianceIdempotencyRequestHash,
  isComplianceIdempotencyPort,
  normalizeComplianceIdempotencyScope,
  type ComplianceIdempotencyPort,
  type ComplianceIdempotencyRecord,
} from "../compliance/idempotency.js";
import { isOpenPlatformComplianceError } from "../compliance/errors.js";
import type { OpenPlatformRequestContext } from "../authorization.js";
import {
  OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY,
  OPEN_PLATFORM_COMPLIANCE_MODE,
} from "./open-platform-compliance.tokens.js";

export interface ComplianceIdempotentWrite<T> {
  readonly operation: string;
  readonly key: string;
  readonly request: unknown;
  readonly action: () => Promise<T>;
}

export interface ComplianceIdempotentResult<T> {
  readonly value: T;
  readonly replayed: boolean;
}

export const COMPLIANCE_IDEMPOTENCY_REPLAY_HEADER = "idempotency-replayed";

@Injectable()
export class OpenPlatformComplianceIdempotency {
  readonly mode: "development" | "test" | "production";
  private readonly store: ComplianceIdempotencyPort;
  private readonly inFlight = new Set<string>();

  constructor(
    @Inject(OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY)
    store: ComplianceIdempotencyPort,
    @Inject(OPEN_PLATFORM_COMPLIANCE_MODE)
    mode: "development" | "test" | "production",
  ) {
    if (!isComplianceIdempotencyPort(store)) {
      throw new Error("[getbrick-idaas] open platform compliance idempotency port is invalid");
    }
    if (mode !== "development" && mode !== "test" && mode !== "production") {
      throw new Error("[getbrick-idaas] open platform compliance mode is invalid");
    }
    this.store = store;
    this.mode = mode;
  }

  async execute<T>(
    context: OpenPlatformRequestContext,
    write: ComplianceIdempotentWrite<T>,
  ): Promise<ComplianceIdempotentResult<T>> {
    const scope = normalizeComplianceIdempotencyScope({
      tenantId: context.tenantId,
      actorId: context.actorId,
      operation: write.operation,
      key: write.key,
    });
    const requestHash = createComplianceIdempotencyRequestHash(
      scope.operation,
      write.request,
    );
    const existing = await this.read(scope);
    if (existing !== undefined) {
      assertComplianceIdempotencyReplayable(existing, requestHash);
      return { value: existing.value as T, replayed: true };
    }
    const storageKey = complianceInFlightKey(scope);
    assertComplianceIdempotencyAvailable(this.inFlight.has(storageKey));
    this.inFlight.add(storageKey);
    try {
      const value = await write.action();
      await this.commit({ scope, requestHash, value });
      return { value, replayed: false };
    } finally {
      this.inFlight.delete(storageKey);
    }
  }

  private async read(
    scope: ReturnType<typeof normalizeComplianceIdempotencyScope>,
  ): Promise<ComplianceIdempotencyRecord | undefined> {
    try {
      return await this.store.get(scope);
    } catch (error) {
      if (isOpenPlatformComplianceError(error)) throw error;
      if (this.mode === "production") complianceIdempotencyStorageUnavailable();
      return undefined;
    }
  }

  private async commit(entry: {
    readonly scope: ReturnType<typeof normalizeComplianceIdempotencyScope>;
    readonly requestHash: string;
    readonly value: unknown;
  }): Promise<void> {
    try {
      await this.store.put({ ...entry, createdAt: new Date().toISOString() });
    } catch (error) {
      if (isOpenPlatformComplianceError(error)) throw error;
      if (this.mode === "production") complianceIdempotencyStorageUnavailable();
    }
  }
}

function complianceInFlightKey(scope: {
  readonly tenantId: string;
  readonly actorId: string;
  readonly operation: string;
  readonly key: string;
}): string {
  return [scope.tenantId, scope.actorId, scope.operation, scope.key].join("\u0000");
}
