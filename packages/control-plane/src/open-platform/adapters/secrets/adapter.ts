import { createHash, randomBytes } from "node:crypto";
import {
  isSecretBindingUsable,
  type SecretBindingListQuery,
  type SecretBindingRecord,
  type SecretBindingRepository,
} from "../../../secret-binding.js";
import {
  configurationError,
  credentialUnavailable,
  forbidden,
  isOpenPlatformDomainError,
  resourceConflict,
  resourceNotFound,
  secretIssuanceFailed,
  validationError,
} from "../../errors.js";
import type {
  CredentialSecretCompensationInput,
  CredentialSecretProvider,
  CredentialSecretRevokeInput,
  OpenPlatformDependencyReadiness,
} from "../../types.js";

export type OpenPlatformSecretVaultReason = "issue" | "rotate";
export type OpenPlatformSecretRevokeReason =
  | "rotate"
  | "revoke"
  | "compensate";

export interface OpenPlatformSecretVaultWriteInput {
  readonly tenantId: string;
  readonly subjectType: string;
  readonly subjectId: string;
  readonly purpose: string;
  readonly reason: OpenPlatformSecretVaultReason;
  readonly secret: string;
  readonly previousReference?: string;
  readonly previousGracePeriodSeconds?: number;
  readonly revokePrevious: boolean;
}

export interface OpenPlatformSecretVaultReadInput {
  readonly tenantId: string;
  readonly reference: string;
  readonly operation: "reveal";
}

export interface OpenPlatformSecretVaultRevokeInput {
  readonly tenantId: string;
  readonly reference: string;
  readonly subjectType: string;
  readonly subjectId: string;
  readonly purpose: string;
  readonly reason: OpenPlatformSecretRevokeReason;
}

export interface OpenPlatformSecretVaultPort {
  readonly productionReady: boolean;
  readonly readiness: OpenPlatformDependencyReadiness;
  write(
    input: OpenPlatformSecretVaultWriteInput,
  ): Promise<{ readonly reference: string }>;
  read(input: OpenPlatformSecretVaultReadInput): Promise<string>;
  revoke(input: OpenPlatformSecretVaultRevokeInput): Promise<void>;
}

export interface ProductionSecretBindingPort extends SecretBindingRepository {
  readonly productionReady?: boolean;
}

export interface OpenPlatformSecretRevealAuthorizationRequest {
  readonly tenantId: string;
  readonly reference: string;
  readonly subjectType: string;
  readonly subjectId: string;
  readonly purpose: string;
}

export interface OpenPlatformSecretRevealAuthorizerPort {
  authorize(
    request: OpenPlatformSecretRevealAuthorizationRequest,
  ): boolean | PromiseLike<boolean>;
}

export interface ProductionSecretAdapterOptions {
  readonly vault: OpenPlatformSecretVaultPort;
  readonly bindings: ProductionSecretBindingPort;
  readonly revealAuthorizer: OpenPlatformSecretRevealAuthorizerPort;
  readonly clock?: () => Date;
  readonly subjectType?: string;
  readonly purpose?: string;
}

export type CredentialSecretIssueInput = Parameters<
  CredentialSecretProvider["issue"]
>[0];

export interface ProductionSecretMaterial {
  readonly secret: string;
  readonly reference: string;
  readonly digest: string;
}

export interface BoundSecretIssueInput {
  readonly tenantId: string;
  readonly subjectType: string;
  readonly subjectId: string;
  readonly purpose: string;
  readonly gracePeriodSeconds?: number;
  readonly validFrom?: Date | string;
}

export interface BoundSecretIssueResult extends ProductionSecretMaterial {
  readonly binding: SecretBindingRecord;
}

export interface BoundSecretRotateInput extends BoundSecretIssueInput {
  readonly expectedVersion?: number;
}

export interface BoundSecretRotateResult extends ProductionSecretMaterial {
  readonly binding: SecretBindingRecord;
  readonly previousBinding: SecretBindingRecord;
}

export type SecretRevokeInput =
  | {
      readonly tenantId: string;
      readonly bindingId: string;
      readonly subjectType?: never;
      readonly subjectId?: never;
      readonly purpose?: never;
      readonly version?: number;
    }
  | {
      readonly tenantId: string;
      readonly bindingId?: never;
      readonly subjectType: string;
      readonly subjectId: string;
      readonly purpose: string;
      readonly version?: never;
    };

export interface SecretCompensateInput {
  readonly tenantId: string;
  readonly reference: string;
  readonly subjectType: string;
  readonly subjectId: string;
  readonly purpose: string;
}

export type SecretRevealInput =
  | {
      readonly tenantId: string;
      readonly reference: string;
      readonly subjectType?: string;
      readonly subjectId?: string;
      readonly purpose?: string;
    }
  | {
      readonly tenantId: string;
      readonly reference?: string;
      readonly subjectType: string;
      readonly subjectId: string;
      readonly purpose: string;
    };

export interface ProductionCredentialSecretProvider
  extends CredentialSecretProvider {
  revoke(input: SecretRevokeInput): Promise<readonly SecretBindingRecord[]>;
  revoke(input: CredentialSecretRevokeInput): Promise<void>;
  compensate(input: SecretCompensateInput): Promise<void>;
  compensate(input: CredentialSecretCompensationInput): Promise<void>;
}

export interface SecretNoStoreHeaders {
  readonly "Cache-Control": "no-store";
  readonly Pragma: "no-cache";
  readonly "Referrer-Policy": "no-referrer";
}

export interface SecretRevealResult {
  readonly secret: string;
  readonly noStore: true;
  readonly headers: SecretNoStoreHeaders;
}

export interface ProductionSecretAdapterReadiness {
  readonly ready: boolean;
  readonly productionReady: boolean;
  readonly storage: "memory" | "persistent";
  readonly distributed: boolean;
  readonly vaultReady: boolean;
  readonly bindingsReady: boolean;
}

export const OPEN_PLATFORM_SECRET_NO_STORE_HEADERS: SecretNoStoreHeaders =
  Object.freeze({
    "Cache-Control": "no-store",
    Pragma: "no-cache",
    "Referrer-Policy": "no-referrer",
  });

export function digestOpenPlatformSecret(secret: string): string {
  const normalized = normalizeSecret(secret);
  return `sha256:${createHash("sha256").update(normalized, "utf8").digest("hex")}`;
}

export class ProductionSecretAdapter
implements ProductionCredentialSecretProvider {
  readonly productionReady: boolean;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly vault: OpenPlatformSecretVaultPort;
  private readonly bindings: ProductionSecretBindingPort;
  private readonly revealAuthorizer: OpenPlatformSecretRevealAuthorizerPort;
  private readonly clock: () => Date;
  private readonly defaultSubjectType: string;
  private readonly defaultPurpose: string;
  private readonly bindingStorage: "memory" | "persistent";
  private readonly bindingDistributed: boolean;
  private readonly bindingProductionReady: boolean;

  constructor(options: ProductionSecretAdapterOptions) {
    if (
      !isRecord(options) ||
      !isVaultPort(options.vault) ||
      !isBindingPort(options.bindings) ||
      !isRevealAuthorizer(options.revealAuthorizer) ||
      (options.clock !== undefined && typeof options.clock !== "function")
    ) {
      throw configurationError("Secret adapter configuration is invalid");
    }
    this.vault = options.vault;
    this.bindings = options.bindings;
    this.revealAuthorizer = options.revealAuthorizer;
    this.clock = options.clock ?? (() => new Date());
    this.defaultSubjectType = normalizeConfigurationText(
      options.subjectType ?? "open-platform-credential",
      128,
    );
    this.defaultPurpose = normalizeConfigurationText(
      options.purpose ?? "credential-secret",
      128,
    );
    const capabilities = bindingCapabilities(this.bindings);
    this.bindingStorage = capabilities.storage;
    this.bindingDistributed = capabilities.distributed;
    this.bindingProductionReady = capabilities.productionReady;
    this.productionReady =
      this.vault.productionReady === true &&
      this.vault.readiness.storage === "persistent" &&
      this.vault.readiness.distributed === true &&
      this.bindingStorage === "persistent" &&
      this.bindingDistributed &&
      this.bindingProductionReady;
    this.readiness = Object.freeze({
      storage: this.bindingStorage === "persistent" &&
        this.vault.readiness.storage === "persistent"
        ? "persistent" as const
        : "memory" as const,
      distributed:
        this.bindingDistributed && this.vault.readiness.distributed === true,
      ready: async () => (await this.readinessDetails()).ready,
    });
  }

  async revoke(input: SecretRevokeInput): Promise<readonly SecretBindingRecord[]>;
  async revoke(input: CredentialSecretRevokeInput): Promise<void>;
  async revoke(
    input: SecretRevokeInput | CredentialSecretRevokeInput,
  ): Promise<readonly SecretBindingRecord[] | void> {
    if (isCredentialSecretRevokeInput(input)) {
      await this.revokeCredentialMaterial(input);
      return undefined;
    }
    return this.revokeBindingMaterial(input);
  }

  async compensate(input: SecretCompensateInput): Promise<void>;
  async compensate(input: CredentialSecretCompensationInput): Promise<void>;
  async compensate(
    input: SecretCompensateInput | CredentialSecretCompensationInput,
  ): Promise<void> {
    if (isCredentialSecretCompensationInput(input)) {
      await this.compensateCredentialMaterial(input);
      return;
    }
    const tenantId = this.normalizeTenant(input?.tenantId);
    const reference = normalizeReference(input?.reference);
    const subjectType = normalizeText(input?.subjectType, 128, "subject type");
    const subjectId = normalizeText(input?.subjectId, 512, "subject id");
    const purpose = normalizeText(input?.purpose, 128, "purpose");
    await this.revokeVault({
      tenantId,
      reference,
      subjectType,
      subjectId,
      purpose,
      reason: "compensate",
    }, credentialUnavailable);
  }

  async issue(input: CredentialSecretIssueInput): Promise<ProductionSecretMaterial> {
    const tenantId = this.normalizeTenant(input?.tenantId);
    const subjectId = normalizeText(input?.credentialId, 512, "credential id");
    normalizeText(input?.applicationId, 512, "application id");
    return this.writeSecret({
      tenantId,
      subjectType: this.defaultSubjectType,
      subjectId,
      purpose: this.defaultPurpose,
      reason: input.reason,
    });
  }

  private async revokeCredentialMaterial(
    input: CredentialSecretRevokeInput,
  ): Promise<void> {
    const tenantId = this.normalizeTenant(input.tenantId);
    normalizeText(input.applicationId, 512, "application id");
    const subjectId = normalizeText(input.credentialId, 512, "credential id");
    if (input.reference === undefined) return;
    const reference = normalizeReference(input.reference);
    await this.revokeVault({
      tenantId,
      reference,
      subjectType: this.defaultSubjectType,
      subjectId,
      purpose: this.defaultPurpose,
      reason: input.reason === "rotation" ? "rotate" : "revoke",
    }, secretIssuanceFailed);
  }

  private async compensateCredentialMaterial(
    input: CredentialSecretCompensationInput,
  ): Promise<void> {
    const tenantId = this.normalizeTenant(input.tenantId);
    normalizeText(input.applicationId, 512, "application id");
    const subjectId = normalizeText(input.credentialId, 512, "credential id");
    if (input.reference === undefined) return;
    const reference = normalizeReference(input.reference);
    await this.revokeVault({
      tenantId,
      reference,
      subjectType: this.defaultSubjectType,
      subjectId,
      purpose: this.defaultPurpose,
      reason: "compensate",
    }, secretIssuanceFailed);
  }

  async issueAndBind(
    input: BoundSecretIssueInput,
  ): Promise<BoundSecretIssueResult> {
    const request = this.normalizeBoundInput(input);
    const material = await this.writeSecret({
      ...request,
      reason: "issue",
    });
    let binding: SecretBindingRecord;
    try {
      binding = await this.bindingTransaction(() =>
        this.bindings.create({
          subjectType: request.subjectType,
          subjectId: request.subjectId,
          purpose: request.purpose,
          secretRef: material.reference,
          ...(request.gracePeriodSeconds === undefined
            ? {}
            : { gracePeriodSeconds: request.gracePeriodSeconds }),
          ...(request.validFrom === undefined
            ? {}
            : { validFrom: request.validFrom }),
        }),
      );
      this.assertBinding(
        binding,
        request.subjectId,
        material.reference,
        false,
        request.subjectType,
        request.purpose,
      );
    } catch {
      await this.compensateMaterial(request.tenantId, request, material.reference);
      throw resourceConflict("Secret binding could not be created");
    }
    return Object.freeze({
      ...material,
      binding: cloneBinding(binding),
    });
  }

  async rotate(input: BoundSecretRotateInput): Promise<BoundSecretRotateResult> {
    const request = this.normalizeBoundInput(input);
    const expectedVersion = normalizeVersion(input.expectedVersion);
    let current: SecretBindingRecord | undefined;
    try {
      const resolution = await this.bindings.resolve(
        request.subjectType,
        request.subjectId,
        request.purpose,
        this.now(),
      );
      if (resolution === undefined) {
        current = undefined;
      } else {
        this.assertRevealBinding(resolution.binding, {
          tenantId: request.tenantId,
          subjectType: request.subjectType,
          subjectId: request.subjectId,
          purpose: request.purpose,
        });
        if (
          resolution.usedGracePeriod ||
          resolution.binding.status !== "active"
        ) {
          current = undefined;
        } else {
          current = resolution.binding;
        }
      }
    } catch {
      throw resourceConflict("Secret binding could not be read");
    }
    if (current === undefined) throw resourceNotFound("secretBinding");
    const previous = current;
    if (expectedVersion !== undefined && expectedVersion !== previous.version) {
      throw resourceConflict("Secret binding version changed");
    }
    const gracePeriodSeconds = normalizeGracePeriod(
      input.gracePeriodSeconds ?? previous.gracePeriodSeconds,
    );
    const material = await this.writeSecret({
      ...request,
      reason: "rotate",
      previousReference: previous.secretRef,
      previousGracePeriodSeconds: gracePeriodSeconds,
      revokePrevious: false,
    });
    let binding: SecretBindingRecord;
    try {
      binding = await this.bindingTransaction(() =>
        this.bindings.rotate(
          request.subjectType,
          request.subjectId,
          request.purpose,
          {
            secretRef: material.reference,
            gracePeriodSeconds,
            ...(input.validFrom === undefined
              ? {}
              : { validFrom: input.validFrom }),
            expectedVersion: previous.version,
          },
        ),
      );
      this.assertBinding(
        binding,
        request.subjectId,
        material.reference,
        false,
        request.subjectType,
        request.purpose,
      );
      if (binding.version !== previous.version + 1) {
        throw new Error("invalid secret binding version");
      }
    } catch {
      await this.compensateMaterial(request.tenantId, request, material.reference);
      throw resourceConflict("Secret binding version changed");
    }
    await this.revokeVault({
      tenantId: request.tenantId,
      reference: previous.secretRef,
      subjectType: request.subjectType,
      subjectId: request.subjectId,
      purpose: request.purpose,
      reason: "rotate",
    }, secretIssuanceFailed);
    return Object.freeze({
      ...material,
      binding: cloneBinding(binding),
      previousBinding: cloneBinding(
        await this.rotatedPreviousBinding(previous, gracePeriodSeconds),
      ),
    });
  }

  private async revokeBindingMaterial(
    input: SecretRevokeInput,
  ): Promise<readonly SecretBindingRecord[]> {
    const tenantId = this.normalizeTenant(input?.tenantId);
    const byId = typeof input?.bindingId === "string";
    const subjectType = byId
      ? undefined
      : normalizeText(input?.subjectType, 128, "subject type");
    const subjectId = byId
      ? undefined
      : normalizeText(input?.subjectId, 512, "subject id");
    const purpose = byId
      ? undefined
      : normalizeText(input?.purpose, 128, "purpose");
    let records: SecretBindingRecord[];
    if (byId) {
      const bindingId = normalizeText(input.bindingId, 512, "binding id");
      const current = await this.safeBindingGet(bindingId);
      if (current === undefined) throw resourceNotFound("secretBinding");
      records = current.status === "revoked"
        ? [current]
        : await this.revokeBinding(current, input.version);
    } else {
      const listed = await this.listBindings({
        subjectType,
        subjectId,
        purpose,
      });
      if (listed.length === 0) throw resourceNotFound("secretBinding");
      for (const binding of listed) {
        this.assertBinding(
          binding,
          subjectId as string,
          binding.secretRef,
          false,
          subjectType,
          purpose,
        );
      }
      const usable = listed.filter((binding) => binding.status !== "revoked");
      records = usable.length === 0
        ? listed
        : await this.revokeSubject(
            subjectType as string,
            subjectId as string,
            purpose as string,
            usable,
          );
    }
    let unavailable = false;
    for (const binding of records) {
      try {
        this.assertBinding(binding, binding.subjectId, binding.secretRef);
        await this.revokeVault({
          tenantId,
          reference: binding.secretRef,
          subjectType: binding.subjectType,
          subjectId: binding.subjectId,
          purpose: binding.purpose,
          reason: "revoke",
        }, credentialUnavailable);
      } catch {
        unavailable = true;
      }
    }
    if (unavailable) throw credentialUnavailable();
    return Object.freeze(records.map(cloneBinding));
  }

  async reveal(input: SecretRevealInput): Promise<SecretRevealResult> {
    const tenantId = this.normalizeTenant(input?.tenantId);
    const binding = await this.revealBinding(input, tenantId);
    let allowed: boolean;
    try {
      allowed = await this.revealAuthorizer.authorize({
        tenantId,
        reference: binding.secretRef,
        subjectType: binding.subjectType,
        subjectId: binding.subjectId,
        purpose: binding.purpose,
      });
    } catch {
      throw credentialUnavailable();
    }
    if (allowed !== true) throw forbidden();
    let secret: string;
    try {
      secret = await this.vault.read({
        tenantId,
        reference: binding.secretRef,
        operation: "reveal",
      });
      secret = normalizeSecret(secret);
    } catch {
      throw credentialUnavailable();
    }
    return Object.freeze({
      secret,
      noStore: true,
      headers: OPEN_PLATFORM_SECRET_NO_STORE_HEADERS,
    });
  }

  async resolveSecret(secretRef: string): Promise<string> {
    return (await this.resolveSecretForReveal(secretRef)).secret;
  }

  async resolveSecretForReveal(
    secretRef: string,
  ): Promise<SecretRevealResult> {
    const reference = normalizeReference(secretRef);
    return this.reveal({
      tenantId: this.bindings.tenant.tenantId,
      reference,
    });
  }

  async isReady(): Promise<boolean> {
    return (await this.readinessDetails()).ready;
  }

  async readinessDetails(): Promise<ProductionSecretAdapterReadiness> {
    const [vaultReady, bindingsReady] = await Promise.all([
      dependencyReady(this.vault.readiness),
      this.safeBindingReady(),
    ]);
    return Object.freeze({
      ready: vaultReady && bindingsReady,
      productionReady: this.productionReady,
      storage: this.readiness.storage,
      distributed: this.readiness.distributed,
      vaultReady,
      bindingsReady,
    });
  }

  async isProductionReady(): Promise<boolean> {
    return this.productionReady && (await this.isReady());
  }

  async assertProductionReady(): Promise<void> {
    if (!(await this.isProductionReady())) {
      throw configurationError("Production secret adapter is not ready");
    }
  }

  private async writeSecret(input: {
    tenantId: string;
    subjectType: string;
    subjectId: string;
    purpose: string;
    reason: "issue" | "rotate";
    previousReference?: string;
    previousGracePeriodSeconds?: number;
    revokePrevious?: boolean;
  }): Promise<ProductionSecretMaterial> {
    let secret: string;
    try {
      secret = randomBytes(32).toString("base64url");
    } catch {
      throw secretIssuanceFailed();
    }
    let written: { readonly reference: string };
    try {
      written = await this.vault.write({
        tenantId: input.tenantId,
        subjectType: input.subjectType,
        subjectId: input.subjectId,
        purpose: input.purpose,
        reason: input.reason,
        secret,
        ...(input.previousReference === undefined
          ? {}
          : { previousReference: input.previousReference }),
        ...(input.previousGracePeriodSeconds === undefined
          ? {}
          : {
              previousGracePeriodSeconds:
                input.previousGracePeriodSeconds,
            }),
        revokePrevious: input.revokePrevious === true,
      });
    } catch {
      throw secretIssuanceFailed();
    }
    let reference: string;
    try {
      reference = normalizeReference(written?.reference);
      if (reference.includes(secret)) {
        throw new Error("invalid secret reference");
      }
    } catch {
      if (typeof written?.reference === "string") {
        await this.compensateReference(
          input.tenantId,
          input.subjectType,
          input.subjectId,
          input.purpose,
          written.reference,
        );
      }
      throw secretIssuanceFailed();
    }
    return Object.freeze({
      secret,
      reference,
      digest: digestOpenPlatformSecret(secret),
    });
  }

  private async revealBinding(
    input: SecretRevealInput,
    tenantId: string,
  ): Promise<SecretBindingRecord> {
    try {
      const reference = typeof input?.reference === "string"
        ? normalizeReference(input.reference)
        : undefined;
      const hasSubjectContext = input?.subjectType !== undefined ||
        input?.subjectId !== undefined ||
        input?.purpose !== undefined;
      if (hasSubjectContext && (
        input.subjectType === undefined ||
        input.subjectId === undefined ||
        input.purpose === undefined
      )) {
        throw validationError("Secret request is invalid", {
          field: "subject context",
        });
      }
      const subjectType = input?.subjectType === undefined
        ? undefined
        : normalizeText(input.subjectType, 128, "subject type");
      const subjectId = input?.subjectId === undefined
        ? undefined
        : normalizeText(input.subjectId, 512, "subject id");
      const purpose = input?.purpose === undefined
        ? undefined
        : normalizeText(input.purpose, 128, "purpose");
      let binding: SecretBindingRecord | undefined;
      const hasCompleteSubject = subjectType !== undefined &&
        subjectId !== undefined &&
        purpose !== undefined;
      if (hasCompleteSubject) {
        const resolution = await this.bindings.resolve(
          subjectType as string,
          subjectId as string,
          purpose as string,
          this.now(),
        );
        binding = resolution?.binding;
      } else if (reference !== undefined) {
        const listed = await this.listBindings({});
        binding = listed.find((candidate) =>
          candidate.secretRef === reference &&
          isSecretBindingUsable(candidate, this.now()),
        );
      } else {
        throw validationError("Secret request is invalid", {
          field: "subject context",
        });
      }
      if (binding === undefined) throw resourceNotFound("secretBinding");
      return this.assertRevealBinding(binding, {
        tenantId,
        ...(reference === undefined ? {} : { reference }),
        ...(subjectType === undefined ? {} : { subjectType }),
        ...(subjectId === undefined ? {} : { subjectId }),
        ...(purpose === undefined ? {} : { purpose }),
      });
    } catch (error) {
      if (isSafeSecretError(error)) throw error;
      throw credentialUnavailable();
    }
  }

  private assertRevealBinding(
    binding: SecretBindingRecord,
    context: {
      tenantId: string;
      reference?: string;
      subjectType?: string;
      subjectId?: string;
      purpose?: string;
    },
  ): SecretBindingRecord {
    if (!isRecord(binding) || typeof binding.tenantId !== "string") {
      throw credentialUnavailable();
    }
    if (binding.tenantId !== context.tenantId) throw forbidden();
    if (
      (context.subjectType !== undefined && binding.subjectType !== context.subjectType) ||
      (context.subjectId !== undefined && binding.subjectId !== context.subjectId) ||
      (context.purpose !== undefined && binding.purpose !== context.purpose)
    ) {
      throw forbidden();
    }
    let reference: string;
    try {
      reference = normalizeReference(binding.secretRef);
    } catch {
      throw credentialUnavailable();
    }
    if (context.reference !== undefined && reference !== context.reference) {
      throw credentialUnavailable();
    }
    if (!isSecretBindingUsable(binding, this.now())) {
      throw resourceNotFound("secretBinding");
    }
    return binding;
  }

  private async rotatedPreviousBinding(
    binding: SecretBindingRecord,
    gracePeriodSeconds: number,
  ): Promise<SecretBindingRecord> {
    try {
      const stored = await this.bindings.get(binding.id);
      if (
        stored !== undefined &&
        stored.status === "retiring" &&
        stored.version === binding.version
      ) {
        return stored;
      }
    } catch {}
    const timestamp = this.now();
    return {
      ...binding,
      status: "retiring",
      gracePeriodSeconds,
      graceUntil: gracePeriodSeconds === 0
        ? null
        : new Date(timestamp.getTime() + gracePeriodSeconds * 1000),
      supersededAt: timestamp,
      updatedAt: timestamp,
    };
  }

  private async revokeBinding(
    binding: SecretBindingRecord,
    version?: number,
  ): Promise<SecretBindingRecord[]> {
    try {
      const revoked = await this.bindingTransaction(() =>
        this.bindings.revoke(binding.id, version),
      );
      this.assertBinding(revoked, binding.subjectId, binding.secretRef);
      return [revoked];
    } catch {
      throw resourceConflict("Secret binding could not be revoked");
    }
  }

  private async revokeSubject(
    subjectType: string,
    subjectId: string,
    purpose: string,
    current: readonly SecretBindingRecord[],
  ): Promise<SecretBindingRecord[]> {
    try {
      const revoked = await this.bindingTransaction(async () => {
        if (typeof this.bindings.revokeSubject === "function") {
          return this.bindings.revokeSubject(subjectType, subjectId, purpose);
        }
        const records: SecretBindingRecord[] = [];
        for (const binding of current) {
          records.push(await this.bindings.revoke(binding.id, binding.version));
        }
        return records;
      });
      if (revoked.length !== current.length) {
        throw new Error("incomplete secret binding revocation");
      }
      for (const binding of revoked) {
        this.assertBinding(
          binding,
          subjectId,
          undefined,
          true,
          subjectType,
          purpose,
        );
      }
      return revoked;
    } catch {
      throw resourceConflict("Secret bindings could not be revoked");
    }
  }

  private async safeBindingGet(
    bindingId: string,
  ): Promise<SecretBindingRecord | undefined> {
    try {
      const binding = await this.bindings.get(bindingId);
      if (binding === undefined) return undefined;
      this.assertTenant(binding.tenantId);
      return binding;
    } catch (error) {
      if (isSafeSecretError(error)) throw error;
      throw credentialUnavailable();
    }
  }

  private async safeBindingReady(): Promise<boolean> {
    try {
      return await this.bindings.isReady() === true;
    } catch {
      return false;
    }
  }

  private async listBindings(
    query: SecretBindingListQuery,
  ): Promise<SecretBindingRecord[]> {
    const records: SecretBindingRecord[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 100; page += 1) {
      const result = await this.bindings.list({
        ...query,
        limit: 100,
        ...(cursor === undefined ? {} : { cursor }),
      });
      for (const binding of result.items) {
        this.assertTenant(binding.tenantId);
        records.push(binding);
      }
      if (!result.hasMore) return records;
      if (result.nextCursor === undefined) {
        throw credentialUnavailable();
      }
      cursor = result.nextCursor;
    }
    throw credentialUnavailable();
  }

  private async bindingTransaction<T>(operation: () => Promise<T>): Promise<T> {
    const transactional = this.bindings as ProductionSecretBindingPort & {
      withTransaction?<T>(operation: () => Promise<T>): Promise<T>;
    };
    if (typeof transactional.withTransaction === "function") {
      return transactional.withTransaction(operation);
    }
    return operation();
  }

  private async revokeVault(
    input: OpenPlatformSecretVaultRevokeInput,
    failure: () => Error,
  ): Promise<void> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        await this.vault.revoke(input);
        return;
      } catch {}
    }
    throw failure();
  }

  private async compensateMaterial(
    tenantId: string,
    input: {
      subjectType: string;
      subjectId: string;
      purpose: string;
    },
    reference: string,
  ): Promise<void> {
    try {
      await this.compensate({
        tenantId,
        reference,
        subjectType: input.subjectType,
        subjectId: input.subjectId,
        purpose: input.purpose,
      });
    } catch {}
  }

  private async compensateReference(
    tenantId: string,
    subjectType: string,
    subjectId: string,
    purpose: string,
    reference: string,
  ): Promise<void> {
    try {
      await this.revokeVault({
        tenantId,
        reference,
        subjectType,
        subjectId,
        purpose,
        reason: "compensate",
      }, credentialUnavailable);
    } catch {}
  }

  private assertBinding(
    binding: SecretBindingRecord,
    subjectId: string,
    reference?: string,
    allowChangedReference = false,
    expectedSubjectType?: string,
    expectedPurpose?: string,
  ): void {
    this.assertTenant(binding?.tenantId);
    normalizeText(binding?.id, 512, "binding id");
    normalizeText(binding?.subjectType, 128, "subject type");
    normalizeText(binding?.purpose, 128, "purpose");
    normalizeReference(binding?.secretRef);
    if (binding.subjectId !== subjectId) {
      throw new Error("invalid secret binding subject");
    }
    if (
      expectedSubjectType !== undefined &&
      binding.subjectType !== expectedSubjectType
    ) {
      throw new Error("invalid secret binding subject type");
    }
    if (
      expectedPurpose !== undefined &&
      binding.purpose !== expectedPurpose
    ) {
      throw new Error("invalid secret binding purpose");
    }
    if (!allowChangedReference && reference !== binding.secretRef) {
      throw new Error("invalid secret binding reference");
    }
    if (!Number.isSafeInteger(binding.version) || binding.version < 1) {
      throw new Error("invalid secret binding version");
    }
  }

  private normalizeBoundInput(input: BoundSecretIssueInput): {
    tenantId: string;
    subjectType: string;
    subjectId: string;
    purpose: string;
    gracePeriodSeconds?: number;
    validFrom?: Date | string;
  } {
    if (!isRecord(input)) {
      throw validationError("Secret request is invalid", { field: "request" });
    }
    const tenantId = this.normalizeTenant(input.tenantId);
    return {
      tenantId,
      subjectType: normalizeText(input.subjectType, 128, "subject type"),
      subjectId: normalizeText(input.subjectId, 512, "subject id"),
      purpose: normalizeText(input.purpose, 128, "purpose"),
      ...(input.gracePeriodSeconds === undefined
        ? {}
        : { gracePeriodSeconds: normalizeGracePeriod(input.gracePeriodSeconds) }),
      ...(input.validFrom === undefined ? {} : { validFrom: input.validFrom }),
    };
  }

  private assertTenant(value: unknown): void {
    if (value !== this.bindings.tenant.tenantId) {
      throw forbidden();
    }
  }

  private normalizeTenant(value: unknown): string {
    const tenantId = normalizeText(value, 256, "tenant id");
    if (tenantId.includes(":")) {
      throw forbidden();
    }
    if (tenantId !== this.bindings.tenant.tenantId) {
      throw forbidden();
    }
    return tenantId;
  }

  private now(): Date {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw configurationError("Secret adapter clock is invalid");
    }
    return new Date(value.getTime());
  }
}

export function createProductionSecretAdapter(
  options: ProductionSecretAdapterOptions,
): ProductionSecretAdapter {
  return new ProductionSecretAdapter(options);
}

export const createVaultSecretAdapter = createProductionSecretAdapter;

export type IdaasSecretResolver = (secretRef: string) => Promise<string>;

export function createIdaasSecretResolver(
  adapter: ProductionSecretAdapter,
): IdaasSecretResolver {
  if (!(adapter instanceof ProductionSecretAdapter)) {
    throw configurationError("Secret resolver adapter is invalid");
  }
  return Object.freeze((secretRef: string) => adapter.resolveSecret(secretRef));
}

export const createSecretResolver = createIdaasSecretResolver;

function isCredentialSecretRevokeInput(
  value: unknown,
): value is CredentialSecretRevokeInput {
  return isRecord(value) &&
    (value.reason === "rotation" || value.reason === "revocation") &&
    typeof value.tenantId === "string" &&
    typeof value.applicationId === "string" &&
    typeof value.credentialId === "string" &&
    typeof value.digest === "string" &&
    (value.reference === undefined || typeof value.reference === "string");
}

function isCredentialSecretCompensationInput(
  value: unknown,
): value is CredentialSecretCompensationInput {
  return isRecord(value) &&
    (value.reason === "issuePersistenceFailed" ||
      value.reason === "rotationPersistenceFailed" ||
      value.reason === "rotationRevokeFailed") &&
    typeof value.tenantId === "string" &&
    typeof value.applicationId === "string" &&
    typeof value.credentialId === "string" &&
    typeof value.digest === "string" &&
    (value.reference === undefined || typeof value.reference === "string");
}

function bindingCapabilities(bindings: ProductionSecretBindingPort): {
  storage: "memory" | "persistent";
  distributed: boolean;
  productionReady: boolean;
} {
  const candidate = bindings as ProductionSecretBindingPort & {
    readiness?: unknown;
  };
  const persistent =
    candidate.productionReady === true ||
    typeof candidate.readiness === "function";
  return {
    storage: persistent ? "persistent" : "memory",
    distributed: persistent,
    productionReady:
      persistent && bindings.tenant.productionReady !== false,
  };
}

async function dependencyReady(
  readiness: OpenPlatformDependencyReadiness,
): Promise<boolean> {
  try {
    return await readiness.ready() === true;
  } catch {
    return false;
  }
}

function isVaultPort(value: unknown): value is OpenPlatformSecretVaultPort {
  return isRecord(value) &&
    typeof value.productionReady === "boolean" &&
    isDependencyReadiness(value.readiness) &&
    typeof value.write === "function" &&
    typeof value.read === "function" &&
    typeof value.revoke === "function";
}

function isBindingPort(value: unknown): value is ProductionSecretBindingPort {
  return isRecord(value) &&
    isRecord(value.tenant) &&
    typeof value.tenant.tenantId === "string" &&
    typeof value.get === "function" &&
    typeof value.resolve === "function" &&
    typeof value.list === "function" &&
    typeof value.create === "function" &&
    typeof value.rotate === "function" &&
    typeof value.revoke === "function" &&
    typeof value.isReady === "function";
}

function isRevealAuthorizer(
  value: unknown,
): value is OpenPlatformSecretRevealAuthorizerPort {
  return isRecord(value) && typeof value.authorize === "function";
}

function isDependencyReadiness(
  value: unknown,
): value is OpenPlatformDependencyReadiness {
  return isRecord(value) &&
    (value.storage === "memory" || value.storage === "persistent") &&
    typeof value.distributed === "boolean" &&
    typeof value.ready === "function";
}

function normalizeConfigurationText(value: unknown, max: number): string {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.trim().length > max ||
    /[\s\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw configurationError("Secret adapter configuration is invalid");
  }
  return value;
}

function normalizeText(
  value: unknown,
  max: number,
  field: string,
): string {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.trim().length > max ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw validationError("Secret request is invalid", { field });
  }
  return value.trim();
}

export function isOpaqueOpenPlatformSecretReference(
  value: unknown,
): value is string {
  return typeof value === "string" &&
    value === value.trim() &&
    value.length >= 8 &&
    value.length <= 2048 &&
    /^[a-z][a-z0-9+.-]{1,31}:\/\/[A-Za-z0-9][A-Za-z0-9._~:/?+=%-]{0,2010}$/u.test(value);
}

function normalizeReference(value: unknown): string {
  if (!isOpaqueOpenPlatformSecretReference(value)) {
    throw validationError("Secret request is invalid", {
      field: "secret reference",
    });
  }
  return value;
}

function normalizeSecret(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw credentialUnavailable();
  }
  return value;
}

function normalizeVersion(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw validationError("Secret request is invalid", {
      field: "expected version",
    });
  }
  return Number(value);
}

function normalizeGracePeriod(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    Number(value) < 0 ||
    Number(value) > 31_536_000
  ) {
    throw validationError("Secret request is invalid", {
      field: "grace period",
    });
  }
  return Number(value);
}

function cloneBinding(binding: SecretBindingRecord): SecretBindingRecord {
  return Object.freeze({ ...binding });
}

function isSafeSecretError(value: unknown): boolean {
  return isOpenPlatformDomainError(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
