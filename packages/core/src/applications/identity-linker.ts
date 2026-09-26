import { createHash } from "node:crypto";
import { ApplicationPlatformError, type PlatformIdentity } from "./platforms.js";

export const PLATFORM_PLACEHOLDER_EMAIL_DOMAIN = "placeholder.invalid";
export const PLACEHOLDER_EMAIL_DOMAIN = PLATFORM_PLACEHOLDER_EMAIL_DOMAIN;
export const DEFAULT_PLATFORM_IDENTITY_LINKING_POLICY = "create" as const;
export const DEFAULT_PLATFORM_IDENTITY_TENANT_ID = "default";

export interface PlatformIdentityScope {
  tenantId: string;
  applicationId: string;
}

export interface PlatformIdentityKeyInput extends PlatformIdentityScope {
  identity: PlatformIdentity | SafePlatformIdentity;
}

export interface PlatformIdentityKeyParts extends PlatformIdentityScope {
  provider: string;
  platform: string;
  providerAppId?: string;
  appId?: string;
  subject: string;
}

export type PlatformIdentityLinkingMode =
  | "create"
  | "link_existing"
  | "link_verified_email"
  | "reject";

export const PLATFORM_IDENTITY_LINKING_MODES = [
  "create",
  "link_existing",
  "link_verified_email",
  "reject",
] as const satisfies readonly PlatformIdentityLinkingMode[];

export type PlatformIdentityLinkingPolicy =
  | PlatformIdentityLinkingMode
  | "create_new"
  | "new"
  | "link"
  | "require_explicit_link"
  | "link_by_verified_email"
  | "deny"
  | {
      mode: PlatformIdentityLinkingMode | "create_new" | "new" | "link" | "require_explicit_link" | "link_by_verified_email" | "deny";
      userId?: string;
    };

export type PlatformIdentityLinkPolicy = PlatformIdentityLinkingPolicy;

export interface NormalizedPlatformIdentityLinkingPolicy {
  mode: PlatformIdentityLinkingMode;
  userId?: string;
}

export interface SafePlatformIdentity {
  provider: string;
  platform: string;
  appId: string;
  subject: string;
  openid?: string;
  unionid?: string;
  nickname?: string;
  avatarUrl?: string;
  email?: string;
  emailVerified?: boolean;
  scopes: string[];
}

export interface PlatformPublicUser {
  id?: string;
  name: string;
  email: string | null;
  emailVerified: boolean;
  image?: string | null;
}

export interface PlatformBetterAuthUser {
  name: string;
  email: string;
  emailVerified: boolean;
  image?: string;
}

export interface PlatformBetterAuthAccount {
  providerId: string;
  accountId: string;
  platform: string;
  appId: string;
  scopes: string[];
  tenantId?: string;
  applicationId?: string;
  providerAppId?: string;
  identityKey?: string;
}

export interface PlatformIdentityProjection {
  identity: SafePlatformIdentity;
  identityKey: string;
  tenantId: string;
  applicationId: string;
  providerAppId: string;
  scope?: PlatformIdentityScope;
  placeholderEmail: boolean;
  internalEmail: string;
  publicEmail: string | null;
  betterAuthUser: PlatformBetterAuthUser;
  betterAuthAccount: PlatformBetterAuthAccount;
  betterAuth: {
    user: PlatformBetterAuthUser;
    account: PlatformBetterAuthAccount;
  };
  publicUser: PlatformPublicUser;
}

export interface PlatformIdentityLinkHostContext {
  userId?: string;
  authenticatedUserId?: string;
}

export interface PlatformIdentityLinkInput {
  applicationId: string;
  platformId: string;
  tenantId?: string;
  identity: PlatformIdentity;
  identityKey?: string;
  projection?: PlatformIdentityProjection;
  policy?: PlatformIdentityLinkingPolicy;
  requestedUserId?: string;
  hostContext?: PlatformIdentityLinkHostContext;
}

export interface PlatformIdentityLinkResult {
  userId: string;
  tenantId?: string;
  applicationId?: string;
  user?: PlatformPublicUser;
  canonicalUser?: PlatformPublicUser;
  account?: PlatformBetterAuthAccount;
  canonicalAccount?: PlatformBetterAuthAccount;
  accountId?: string;
  created?: boolean;
  linked?: boolean;
}

export interface PlatformIdentityLinker {
  link(input: PlatformIdentityLinkInput): PlatformIdentityLinkResult | Promise<PlatformIdentityLinkResult>;
}

export interface PlatformIdentityCreateUserInput {
  applicationId: string;
  platformId: string;
  tenantId?: string;
  identity: SafePlatformIdentity;
  identityKey: string;
  projection: PlatformIdentityProjection;
}

export interface PlatformIdentityLinkAccountInput extends PlatformIdentityCreateUserInput {
  userId: string;
}

/**
 * The host owns the user/account rows. `createUser` and `linkIdentity` must
 * enforce identity-key uniqueness atomically and must never accept provider
 * credentials or tokens through this interface.
 */
export interface PlatformIdentityLinkStore {
  findByIdentity(
    identityKey: string,
    context?: {
      tenantId?: string;
      applicationId: string;
      platformId: string;
      identity: PlatformIdentity;
      identityKey?: string;
    },
  ): PlatformIdentityLinkResult | null | undefined | Promise<PlatformIdentityLinkResult | null | undefined>;
  findByEmail?(
    email: string,
    context?: {
      tenantId?: string;
      applicationId: string;
      platformId: string;
      identity: PlatformIdentity;
      identityKey?: string;
    },
  ): PlatformIdentityLinkResult | null | undefined | Promise<PlatformIdentityLinkResult | null | undefined>;
  createUser(input: PlatformIdentityCreateUserInput): PlatformIdentityLinkResult | Promise<PlatformIdentityLinkResult>;
  linkIdentity(input: PlatformIdentityLinkAccountInput): PlatformIdentityLinkResult | Promise<PlatformIdentityLinkResult>;
}

export interface BetterAuthPlatformIdentityAdapter extends PlatformIdentityLinkStore {}

export class ExplicitPlatformIdentityLinker implements PlatformIdentityLinker {
  private readonly store: PlatformIdentityLinkStore;

  constructor(store: PlatformIdentityLinkStore) {
    if (
      !store ||
      typeof store.findByIdentity !== "function" ||
      typeof store.createUser !== "function" ||
      typeof store.linkIdentity !== "function"
    ) {
      throw new ApplicationPlatformError("invalid_identity_linker", "Platform identity linker is invalid");
    }
    this.store = store;
  }

  async link(input: PlatformIdentityLinkInput): Promise<PlatformIdentityLinkResult> {
    if (!input || typeof input !== "object") {
      throw new ApplicationPlatformError("invalid_identity_link_input", "Platform identity link input is invalid");
    }
    const tenantId = assertTenantId(input.tenantId ?? DEFAULT_PLATFORM_IDENTITY_TENANT_ID);
    const applicationId = assertIdentifier(input.applicationId, "application");
    const platformId = assertIdentifier(input.platformId, "platform");
    const identity = sanitizePlatformIdentity(input.identity);
    const scope: PlatformIdentityScope = { tenantId, applicationId };
    const computedIdentityKey = createPlatformIdentityKey(identity, scope);
    const identityKey = input.identityKey === undefined
      ? computedIdentityKey
      : assertIdentityKey(input.identityKey);
    if (identityKey !== computedIdentityKey) {
      throw new ApplicationPlatformError("invalid_platform_identity", "Platform identity key does not match identity");
    }
    const projection = projectPlatformIdentity(identity, identityKey, scope);
    const policy = normalizePlatformIdentityLinkingPolicy(input.policy);
    const requestedUserId = input.requestedUserId === undefined
      ? undefined
      : assertIdentifier(input.requestedUserId, "user");
    if (requestedUserId !== undefined && policy.mode !== "link_existing") {
      throw new ApplicationPlatformError("invalid_identity_linking_policy", "Only explicit account linking accepts a user target");
    }
    if (requestedUserId !== undefined && policy.userId !== undefined && requestedUserId !== policy.userId) {
      throw new ApplicationPlatformError("invalid_identity_linking_policy", "Platform identity linking targets conflict");
    }
    assertPlatformIdentityLinkHostContext(
      policy,
      requestedUserId ?? policy.userId,
      input.hostContext,
    );
    const targetUserId = requestedUserId ?? policy.userId;
    const existing = normalizeOptionalLinkResult(await this.store.findByIdentity(identityKey, {
      tenantId,
      applicationId,
      platformId,
      identity,
      identityKey,
    }));
    if (existing !== undefined) {
      assertResultScope(existing, scope, identityKey);
      if (targetUserId !== undefined && existing.userId !== targetUserId) {
        throw new ApplicationPlatformError("identity_link_target_mismatch", "Platform identity is already linked to another user");
      }
      return {
        ...existing,
        tenantId,
        applicationId,
        created: false,
        linked: true,
      };
    }
    if (policy.mode === "reject") {
      throw new ApplicationPlatformError("identity_linking_rejected", "Platform identity cannot be linked by this policy");
    }
    if (policy.mode === "link_existing") {
      if (targetUserId === undefined) {
        throw new ApplicationPlatformError("explicit_identity_link_required", "Platform identity linking requires an explicit user");
      }
      const linked = normalizeLinkResult(
        await this.store.linkIdentity({
          tenantId,
          applicationId,
          platformId,
          userId: targetUserId,
          identity,
          identityKey,
          projection,
        }),
      );
      if (linked.userId !== targetUserId) {
        throw new ApplicationPlatformError("identity_link_target_mismatch", "Platform identity linked to an unexpected user");
      }
      assertResultScope(linked, scope, identityKey);
      return { ...linked, tenantId, applicationId, created: false, linked: true };
    }
    if (policy.mode === "link_verified_email") {
      if (identity.email === undefined || identity.emailVerified !== true) {
        throw new ApplicationPlatformError("verified_email_required", "Platform identity email is not verified");
      }
      if (typeof this.store.findByEmail !== "function") {
        throw new ApplicationPlatformError("identity_email_lookup_unavailable", "Platform identity email lookup is unavailable");
      }
      const emailMatch = normalizeOptionalLinkResult(await this.store.findByEmail(identity.email, {
        tenantId,
        applicationId,
        platformId,
        identity,
        identityKey,
      }));
      if (emailMatch === undefined) {
        throw new ApplicationPlatformError("identity_link_not_found", "No existing user matches the verified platform email");
      }
      assertResultScope(emailMatch, scope, identityKey);
      if (emailMatch.user !== undefined && emailMatch.user.emailVerified !== true) {
        throw new ApplicationPlatformError("verified_local_email_required", "Existing user email is not verified");
      }
      const linked = normalizeLinkResult(
        await this.store.linkIdentity({
          tenantId,
          applicationId,
          platformId,
          userId: emailMatch.userId,
          identity,
          identityKey,
          projection,
        }),
      );
      if (linked.userId !== emailMatch.userId) {
        throw new ApplicationPlatformError("identity_link_target_mismatch", "Platform identity linked to an unexpected user");
      }
      assertResultScope(linked, scope, identityKey);
      return { ...linked, tenantId, applicationId, created: false, linked: true };
    }
    if (identity.email !== undefined && typeof this.store.findByEmail === "function") {
      const emailMatch = await this.store.findByEmail(identity.email, {
        tenantId,
        applicationId,
        platformId,
        identity,
        identityKey,
      });
      if (emailMatch !== undefined && emailMatch !== null) {
        throw new ApplicationPlatformError("identity_email_conflict", "Platform identity email is already in use");
      }
    }
    const created = normalizeLinkResult(
      await this.store.createUser({
        tenantId,
        applicationId,
        platformId,
        identity,
        identityKey,
        projection,
      }),
    );
    assertResultScope(created, scope, identityKey);
    return {
      ...created,
      tenantId,
      applicationId,
      created: created.created !== false,
      linked: false,
    };
  }
}

export function createPlatformIdentityLinker(store: PlatformIdentityLinkStore): ExplicitPlatformIdentityLinker {
  return new ExplicitPlatformIdentityLinker(store);
}

export function assertPlatformIdentityLinkHostContext(
  policy: PlatformIdentityLinkingPolicy | NormalizedPlatformIdentityLinkingPolicy,
  targetUserId: string | undefined,
  context: PlatformIdentityLinkHostContext | undefined,
): void {
  const normalized = normalizePlatformIdentityLinkingPolicy(policy);
  const hostUserId = resolveHostUserId(context);
  if (normalized.mode !== "link_existing") {
    if (hostUserId !== undefined && targetUserId !== undefined && hostUserId !== targetUserId) {
      throw new ApplicationPlatformError("invalid_host_context", "Platform host context is inconsistent");
    }
    return;
  }
  if (hostUserId === undefined) {
    throw new ApplicationPlatformError("identity_link_authorization_required", "Explicit account linking requires host authorization");
  }
  if (targetUserId === undefined) {
    throw new ApplicationPlatformError("explicit_identity_link_required", "Platform identity linking requires an explicit user");
  }
  if (hostUserId !== targetUserId) {
    throw new ApplicationPlatformError("invalid_host_context", "Platform host context is inconsistent");
  }
}

export function normalizePlatformIdentityLinkingPolicy(
  value: PlatformIdentityLinkingPolicy | undefined,
): NormalizedPlatformIdentityLinkingPolicy {
  if (value === undefined) return { mode: DEFAULT_PLATFORM_IDENTITY_LINKING_POLICY };
  if (typeof value === "string") {
    return { mode: normalizePolicyMode(value) };
  }
  if (!isRecord(value) || typeof value.mode !== "string") {
    throw new ApplicationPlatformError("invalid_identity_linking_policy", "Platform identity linking policy is invalid");
  }
  const mode = normalizePolicyMode(value.mode);
  if (value.userId === undefined) return { mode };
  if (mode === "create" || mode === "reject") {
    throw new ApplicationPlatformError("invalid_identity_linking_policy", "Platform identity linking policy cannot target a user");
  }
  return { mode, userId: assertIdentifier(value.userId, "user") };
}

export function projectPlatformIdentity(
  identityInput: PlatformIdentity | SafePlatformIdentity,
  identityKeyInput?: string | PlatformIdentityScope,
  scopeInput?: PlatformIdentityScope | string,
  applicationIdInput?: string,
): PlatformIdentityProjection {
  const identity = sanitizePlatformIdentity(identityInput);
  const scope = normalizeIdentityScope(
    isIdentityScope(identityKeyInput)
      ? identityKeyInput
      : typeof scopeInput === "string"
        ? { tenantId: scopeInput, applicationId: applicationIdInput ?? "default" }
        : scopeInput,
  );
  const identityKeyValue = typeof identityKeyInput === "string" ? identityKeyInput : undefined;
  const computedIdentityKey = createPlatformIdentityKey(identity, scope);
  const identityKey = identityKeyValue === undefined
    ? computedIdentityKey
    : assertIdentityKey(identityKeyValue);
  if (identityKey !== computedIdentityKey) {
    throw new ApplicationPlatformError("invalid_platform_identity", "Platform identity key does not match identity");
  }
  const placeholderEmail = identity.email === undefined;
  const publicEmail = identity.email ?? null;
  const internalEmail = identity.email ?? createPlaceholderEmail(identityKey);
  const name = identity.nickname ?? `${identity.platform} user`;
  const image = identity.avatarUrl;
  const betterAuthUser: PlatformBetterAuthUser = {
    name,
    email: internalEmail,
    emailVerified: placeholderEmail ? false : identity.emailVerified === true,
    ...(image === undefined ? {} : { image }),
  };
  const betterAuthAccount: PlatformBetterAuthAccount = {
    providerId: identityKey,
    accountId: identity.subject,
    platform: identity.platform,
    appId: identity.appId,
    scopes: [...identity.scopes],
    tenantId: scope.tenantId,
    applicationId: scope.applicationId,
    providerAppId: identity.appId,
    identityKey,
  };
  const publicUser: PlatformPublicUser = {
    name,
    email: publicEmail,
    emailVerified: betterAuthUser.emailVerified,
    ...(image === undefined ? {} : { image }),
  };
  return {
    identity,
    identityKey,
    tenantId: scope.tenantId,
    applicationId: scope.applicationId,
    providerAppId: identity.appId,
    scope,
    placeholderEmail,
    internalEmail,
    publicEmail,
    betterAuthUser,
    betterAuthAccount,
    betterAuth: {
      user: betterAuthUser,
      account: betterAuthAccount,
    },
    publicUser,
  };
}

export function sanitizePlatformIdentity(value: unknown): SafePlatformIdentity {
  if (!isRecord(value)) {
    throw new ApplicationPlatformError("invalid_platform_identity", "Platform provider returned an invalid identity");
  }
  const provider = requiredText(value.provider, "provider");
  const platform = requiredText(value.platform ?? value.provider, "platform");
  const appId = requiredText(value.providerAppId ?? value.appId, "application");
  const subject = requiredText(value.subject, "subject");
  const output: SafePlatformIdentity = {
    provider,
    platform,
    appId,
    subject,
    scopes: normalizeScopes(value.scopes),
  };
  const openid = optionalText(value.openid, "openid");
  const unionid = optionalText(value.unionid, "unionid");
  const nickname = optionalText(value.nickname, "nickname");
  const avatarUrl = optionalUrl(value.avatarUrl, "avatar");
  const hasEmail = value.email !== undefined && value.email !== null && value.email !== "";
  const email = normalizeEmail(value.email);
  if (hasEmail && email === undefined) {
    throw new ApplicationPlatformError("invalid_platform_identity", "Platform provider returned an invalid email");
  }
  if (openid !== undefined) output.openid = openid;
  if (unionid !== undefined) output.unionid = unionid;
  if (nickname !== undefined) output.nickname = nickname;
  if (avatarUrl !== undefined) output.avatarUrl = avatarUrl;
  if (email !== undefined) {
    output.email = email;
    output.emailVerified = value.emailVerified === true;
  } else if (value.emailVerified === true) {
    throw new ApplicationPlatformError("invalid_platform_identity", "Platform provider returned an invalid email verification flag");
  }
  return output;
}

export function createPlatformIdentityKey(
  identityInput: PlatformIdentity | SafePlatformIdentity | PlatformIdentityKeyInput | PlatformIdentityKeyParts,
  scopeInput?: PlatformIdentityScope | string,
  applicationIdInput?: string,
): string {
  if (isRecord(identityInput) && isRecord(identityInput.identity)) {
    const scoped = identityInput as PlatformIdentityKeyInput;
    return createPlatformIdentityKey(scoped.identity, {
      tenantId: scoped.tenantId,
      applicationId: scoped.applicationId,
    });
  }
  if (isRecord(identityInput) && typeof identityInput.provider === "string" && typeof identityInput.subject === "string" && (typeof identityInput.providerAppId === "string" || (typeof identityInput.appId === "string" && !("scopes" in identityInput)))) {
    const parts = identityInput as PlatformIdentityKeyParts;
    return createPlatformIdentityKey({
      provider: parts.provider,
      platform: parts.platform,
      appId: requiredText(parts.providerAppId ?? parts.appId, "application"),
      subject: parts.subject,
      scopes: [],
    }, {
      tenantId: parts.tenantId,
      applicationId: parts.applicationId,
    });
  }
  const identity = sanitizePlatformIdentity(identityInput);
  const scope = normalizeIdentityScope(
    typeof scopeInput === "string"
      ? { tenantId: scopeInput, applicationId: applicationIdInput ?? "default" }
      : scopeInput,
  );
  return [
    scope.tenantId,
    scope.applicationId,
    identity.provider,
    identity.platform,
    identity.appId,
    identity.subject,
  ]
    .map((value) => encodeURIComponent(value))
    .join("|");
}

export const createCanonicalPlatformIdentityKey = createPlatformIdentityKey;
export const createPlatformIdentityScopeKey = createPlatformIdentityKey;
export const createPlatformIdentityCanonicalKey = createPlatformIdentityKey;

export function createPlaceholderEmail(identityKey: string): string {
  const digest = createHash("sha256").update(assertIdentityKey(identityKey), "utf8").digest("hex").slice(0, 40);
  return `platform-${digest}@${PLATFORM_PLACEHOLDER_EMAIL_DOMAIN}`;
}

export function toPublicPlatformUser(
  projection: PlatformIdentityProjection,
  userId?: string,
): PlatformPublicUser {
  return {
    ...(userId === undefined ? {} : { id: assertIdentifier(userId, "user") }),
    name: projection.publicUser.name,
    email: projection.publicUser.email,
    emailVerified: projection.publicUser.emailVerified,
    ...(projection.publicUser.image === undefined ? {} : { image: projection.publicUser.image }),
  };
}

export function toPublicPlatformIdentity(identityInput: PlatformIdentity | SafePlatformIdentity): Omit<SafePlatformIdentity, "email"> & { email: string | null } {
  const identity = sanitizePlatformIdentity(identityInput);
  return {
    ...identity,
    email: identity.email ?? null,
  };
}

function resolveHostUserId(context: PlatformIdentityLinkHostContext | undefined): string | undefined {
  if (context === undefined) return undefined;
  if (!isRecord(context)) {
    throw new ApplicationPlatformError("invalid_host_context", "Platform host context is invalid");
  }
  const userId = context.userId === undefined ? undefined : assertIdentifier(context.userId, "user");
  const authenticatedUserId = context.authenticatedUserId === undefined
    ? undefined
    : assertIdentifier(context.authenticatedUserId, "user");
  if (userId !== undefined && authenticatedUserId !== undefined && userId !== authenticatedUserId) {
    throw new ApplicationPlatformError("invalid_host_context", "Platform host context is inconsistent");
  }
  return userId ?? authenticatedUserId;
}

function normalizePolicyMode(value: string): PlatformIdentityLinkingMode {
  switch (value) {
    case "create":
    case "create_new":
    case "new":
      return "create";
    case "link":
    case "link_existing":
    case "require_explicit_link":
      return "link_existing";
    case "link_by_verified_email":
    case "link_verified_email":
      return "link_verified_email";
    case "deny":
    case "reject":
      return "reject";
    default:
      throw new ApplicationPlatformError("invalid_identity_linking_policy", "Platform identity linking policy is invalid");
  }
}

function normalizeOptionalLinkResult(value: unknown): PlatformIdentityLinkResult | undefined {
  if (value === undefined || value === null) return undefined;
  return normalizeLinkResult(value);
}

export function normalizePlatformIdentityLinkResult(value: unknown): PlatformIdentityLinkResult {
  if (!isRecord(value)) {
    throw new ApplicationPlatformError("identity_linking_failed", "Platform identity linking failed");
  }
  const userId = assertIdentifier(value.userId, "user");
  const userValue = value.canonicalUser ?? value.user;
  const accountValue = value.canonicalAccount ?? value.account;
  const user = userValue === undefined ? undefined : normalizePublicUser(userValue);
  const account = accountValue === undefined ? undefined : normalizeBetterAuthAccount(accountValue);
  const accountId = value.accountId === undefined ? undefined : requiredText(value.accountId, "account");
  return {
    userId,
    ...(value.tenantId === undefined ? {} : { tenantId: assertTenantId(value.tenantId) }),
    ...(value.applicationId === undefined ? {} : { applicationId: assertIdentifier(value.applicationId, "application") }),
    ...(user === undefined ? {} : { user }),
    ...(account === undefined ? {} : { account }),
    ...(accountId === undefined ? {} : { accountId }),
    created: value.created === true,
    linked: value.linked === true,
  };
}

const normalizeLinkResult = normalizePlatformIdentityLinkResult;

function normalizeBetterAuthAccount(value: unknown): PlatformBetterAuthAccount {
  if (!isRecord(value)) {
    throw new ApplicationPlatformError("invalid_identity_link_result", "Platform identity linker returned an invalid account");
  }
  const providerId = requiredText(value.providerId, "provider");
  const accountId = requiredText(value.accountId, "account");
  const platform = requiredText(value.platform, "platform");
  const providerAppId = requiredText(value.providerAppId ?? value.appId, "application");
  const scopes = normalizeScopes(value.scopes);
  return {
    providerId,
    accountId,
    platform,
    appId: providerAppId,
    scopes,
    ...(value.tenantId === undefined ? {} : { tenantId: assertTenantId(value.tenantId) }),
    ...(value.applicationId === undefined ? {} : { applicationId: assertIdentifier(value.applicationId, "application") }),
    providerAppId,
    ...(value.identityKey === undefined ? {} : { identityKey: assertIdentityKey(value.identityKey) }),
  };
}

function normalizePublicUser(value: unknown): PlatformPublicUser {
  if (!isRecord(value)) {
    throw new ApplicationPlatformError("invalid_identity_link_result", "Platform identity linker returned an invalid user");
  }
  const normalizedEmail = value.email === null || value.email === undefined ? undefined : normalizeEmail(value.email);
  if (value.email !== undefined && value.email !== null && normalizedEmail === undefined) {
    throw new ApplicationPlatformError("invalid_identity_link_result", "Platform identity linker returned an invalid user");
  }
  const email = normalizedEmail ?? null;
  const name = value.name === null || value.name === undefined ? "Platform user" : requiredText(value.name, "name");
  const image = value.image === null || value.image === undefined ? undefined : optionalUrl(value.image, "image");
  return {
    ...(typeof value.id === "string" ? { id: requiredText(value.id, "user") } : {}),
    name,
    email,
    emailVerified: value.emailVerified === true,
    ...(image === undefined ? {} : { image }),
  };
}

function normalizeEmail(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  if (
    normalized.length === 0 ||
    normalized.length > 320 ||
    /[\u0000-\u001f\u007f\s]/u.test(normalized) ||
    !normalized.includes("@") ||
    normalized.endsWith(`@${PLATFORM_PLACEHOLDER_EMAIL_DOMAIN}`)
  ) {
    return undefined;
  }
  return normalized;
}

function normalizeScopes(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const output: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") continue;
    const normalized = item.trim();
    if (normalized.length === 0 || normalized.length > 128 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) continue;
    if (!output.includes(normalized)) output.push(normalized);
    if (output.length >= 32) break;
  }
  return output;
}

function requiredText(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_identity", `Platform provider omitted ${field}`);
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 1024 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_platform_identity", `Platform provider returned an invalid ${field}`);
  }
  return normalized;
}

function optionalText(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return requiredText(value, field);
}

function optionalUrl(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const normalized = requiredText(value, field);
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new ApplicationPlatformError("invalid_platform_identity", `Platform provider returned an invalid ${field}`);
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== ""
  ) {
    throw new ApplicationPlatformError("invalid_platform_identity", `Platform provider returned an invalid ${field}`);
  }
  return parsed.toString();
}

function isIdentityScope(value: unknown): value is PlatformIdentityScope {
  return isRecord(value) && typeof value.tenantId === "string" && typeof value.applicationId === "string";
}

function normalizeIdentityScope(value: PlatformIdentityScope | undefined): PlatformIdentityScope {
  return {
    tenantId: assertTenantId(value?.tenantId ?? DEFAULT_PLATFORM_IDENTITY_TENANT_ID),
    applicationId: assertIdentifier(value?.applicationId ?? "default", "application"),
  };
}

function assertTenantId(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_identifier", "Platform tenant identifier is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[:\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_platform_identifier", "Platform tenant identifier is invalid");
  }
  return normalized;
}

function assertResultScope(result: PlatformIdentityLinkResult, scope: PlatformIdentityScope, identityKey?: string): void {
  if (result.tenantId !== undefined && result.tenantId !== scope.tenantId) {
    throw new ApplicationPlatformError("identity_link_scope_mismatch", "Platform identity linker returned another tenant");
  }
  if (result.applicationId !== undefined && result.applicationId !== scope.applicationId) {
    throw new ApplicationPlatformError("identity_link_scope_mismatch", "Platform identity linker returned another application");
  }
  if (result.user?.id !== undefined && result.user.id !== result.userId) {
    throw new ApplicationPlatformError("identity_link_scope_mismatch", "Platform identity linker returned another user");
  }
  if (result.account?.tenantId !== undefined && result.account.tenantId !== scope.tenantId) {
    throw new ApplicationPlatformError("identity_link_scope_mismatch", "Platform identity linker returned another tenant");
  }
  if (result.account?.applicationId !== undefined && result.account.applicationId !== scope.applicationId) {
    throw new ApplicationPlatformError("identity_link_scope_mismatch", "Platform identity linker returned another application");
  }
  if (identityKey !== undefined && result.account?.identityKey !== undefined && result.account.identityKey !== identityKey) {
    throw new ApplicationPlatformError("identity_link_scope_mismatch", "Platform identity linker returned another identity scope");
  }
}

function assertIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_identifier", `Platform ${field} identifier is invalid`);
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_platform_identifier", `Platform ${field} identifier is invalid`);
  }
  return normalized;
}

function assertIdentityKey(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_identity", "Platform identity key is invalid");
  }
  if (value.length === 0 || value.length > 2048 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new ApplicationPlatformError("invalid_platform_identity", "Platform identity key is invalid");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
