import { normalizeOrigin } from "../config";
import { AuthError } from "./errors";
import { createMemoryStorage, type KeyValueStorage } from "../types/runtime";

export type OidcTransactionClientType = "web" | "native" | "webview";

export interface PkceTransaction {
  flowId: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  codeChallenge: string;
  redirectUri: string;
  origin: string;
  clientType: OidcTransactionClientType;
  startGeneration: number;
  attempt: number;
  serverFlowId?: string;
  serverTransactionId?: string;
  createdAt: number;
}

export interface PkceOptions {
  redirectUri: string;
  origin?: string;
  clientType?: OidcTransactionClientType;
  flowId?: string;
  startGeneration?: number;
  attempt?: number;
  now?: () => number;
  randomBytes?: (length: number) => Uint8Array;
  sha256?: (value: Uint8Array) => Promise<ArrayBuffer>;
}

export type OidcTransactionPatch = Partial<Pick<PkceTransaction, "state" | "serverFlowId" | "serverTransactionId">>;

export interface OidcTransactionStoreOptions {
  storage?: KeyValueStorage;
  now?: () => number;
  key?: string;
}

export interface OidcFlowFence {
  readonly generation: number;
  readonly attempt: number;
}

export interface OidcFlowFenceStoreOptions {
  storage?: KeyValueStorage;
  key?: string;
}

export const MAX_OIDC_TRANSACTION_AGE_MS = 10 * 60 * 1000;
export const OIDC_TRANSACTION_TTL_MS = 10 * 60 * 1000;
export const OIDC_TRANSACTION_STORAGE_KEY = "getbrick.client.oidc-transaction";
export const OIDC_FLOW_FENCE_STORAGE_KEY = `${OIDC_TRANSACTION_STORAGE_KEY}.fence`;
export const OIDC_TRANSACTION_STORAGE_PREFIX = `${OIDC_TRANSACTION_STORAGE_KEY}.`;

export class OidcFlowFenceStore {
  private readonly storage: KeyValueStorage;
  private readonly key: string;

  constructor(options: OidcFlowFenceStoreOptions = {}) {
    this.storage = options.storage ?? createMemoryStorage();
    this.key = options.key ?? OIDC_FLOW_FENCE_STORAGE_KEY;
  }

  load(): OidcFlowFence {
    const raw = this.storage.get(this.key);
    if (raw === undefined || raw.length === 0) return { generation: 0, attempt: 1 };
    try {
      return normalizeFlowFence(JSON.parse(raw) as unknown);
    } catch {
      throw new AuthError("invalid_oidc_transaction", "OIDC flow fence is invalid", 409, false);
    }
  }

  begin(): OidcFlowFence {
    return this.advance();
  }

  invalidate(): OidcFlowFence {
    return this.advance();
  }

  isCurrent(fence: OidcFlowFence): boolean {
    try {
      const current = this.load();
      return current.generation === fence.generation && current.attempt === fence.attempt;
    } catch {
      return false;
    }
  }

  assertCurrent(fence: OidcFlowFence): void {
    if (!this.isCurrent(fence)) throw new AuthError("oidc_flow_mismatch", "OIDC transaction is no longer active", 409, false);
  }

  private advance(): OidcFlowFence {
    const current = this.load();
    if (current.generation >= Number.MAX_SAFE_INTEGER || current.attempt >= Number.MAX_SAFE_INTEGER) {
      throw new AuthError("invalid_oidc_transaction", "OIDC flow fence is exhausted", 409, false);
    }
    const next = current.generation === 0
      ? { generation: 1, attempt: 1 }
      : { generation: current.generation + 1, attempt: current.attempt + 1 };
    this.storage.set(this.key, JSON.stringify(next));
    return next;
  }
}

export async function createPkceTransaction(options: PkceOptions): Promise<PkceTransaction> {
  const redirectUri = assertSafeRedirectUri(options.redirectUri);
  const randomBytes = options.randomBytes ?? secureRandomBytes;
  const sha256 = options.sha256 ?? secureSha256;
  const flowId = options.flowId === undefined
    ? encodeBase64Url(assertByteLength(randomBytes(16), 16))
    : readFlowId(options.flowId);
  const state = encodeBase64Url(assertByteLength(randomBytes(32), 32));
  const nonce = encodeBase64Url(assertByteLength(randomBytes(32), 32));
  const codeVerifier = encodeBase64Url(assertByteLength(randomBytes(48), 48));
  const codeChallenge = encodeBase64Url(new Uint8Array(await sha256(utf8ToBytes(codeVerifier))));
  const origin = normalizeTransactionOrigin(options.origin ?? originFromRedirectUri(redirectUri));
  const clientType = options.clientType ?? "web";
  assertBase64Url(flowId, 16, 128);
  assertBase64Url(state, 32, 512);
  assertBase64Url(nonce, 32, 512);
  assertBase64Url(codeVerifier, 43, 128);
  assertBase64Url(codeChallenge, 43, 128);
  if (clientType !== "web" && clientType !== "native" && clientType !== "webview") {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
  }
  const now = options.now ?? Date.now;
  const createdAt = now();
  if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
  }
  const startGeneration = normalizeCounter(options.startGeneration);
  const attempt = normalizeAttempt(options.attempt);
  return { flowId, state, nonce, codeVerifier, codeChallenge, redirectUri, origin, clientType, startGeneration, attempt, createdAt };
}

export class OidcTransactionStore {
  private readonly storage: KeyValueStorage;
  private readonly now: () => number;
  private readonly keyPrefix: string;
  private readonly indexKey: string;

  constructor(options: OidcTransactionStoreOptions = {}) {
    this.storage = options.storage ?? createMemoryStorage();
    this.now = options.now ?? Date.now;
    this.keyPrefix = options.key ?? OIDC_TRANSACTION_STORAGE_KEY;
    this.indexKey = `${this.keyPrefix}.index`;
  }

  save(transaction: PkceTransaction): PkceTransaction;
  save(flowId: string, transaction: Omit<PkceTransaction, "flowId"> | PkceTransaction): PkceTransaction;
  save(transactionOrFlowId: PkceTransaction | string, value?: Omit<PkceTransaction, "flowId"> | PkceTransaction): PkceTransaction {
    const transaction = typeof transactionOrFlowId === "string"
      ? { ...(value as Omit<PkceTransaction, "flowId">), flowId: transactionOrFlowId }
      : transactionOrFlowId;
    const normalized = normalizeTransaction(transaction, this.now());
    const key = this.transactionKey(normalized.flowId);
    const existing = this.storage.get(key);
    if (existing !== undefined && existing.length > 0) {
      throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
    }
    this.storage.set(key, JSON.stringify(normalized));
    const index = this.readIndex();
    index[normalized.flowId] = normalized.createdAt;
    this.storage.set(this.indexKey, JSON.stringify(index));
    return normalized;
  }

  load(flowId?: string): PkceTransaction | null {
    const resolvedFlowId = flowId ?? this.findFlowId();
    if (resolvedFlowId === null) return null;
    const key = this.transactionKey(resolvedFlowId);
    const raw = this.storage.get(key) ?? this.readLegacyRaw(resolvedFlowId);
    if (raw === undefined || raw.length === 0) return null;
    try {
      const transaction = normalizeTransaction(JSON.parse(raw) as unknown, this.now());
      if (transaction.flowId !== resolvedFlowId) throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
      return transaction;
    } catch {
      this.removeRaw(resolvedFlowId, key);
      return null;
    }
  }

  get(flowId: string): PkceTransaction | null {
    return this.load(flowId);
  }

  set(flowId: string, transaction: Omit<PkceTransaction, "flowId"> | PkceTransaction): PkceTransaction {
    return this.save({ ...transaction, flowId });
  }

  update(flowId: string, patch: OidcTransactionPatch): PkceTransaction {
    const current = this.load(flowId);
    if (current === null) throw new AuthError("invalid_oidc_transaction", "OIDC transaction is unavailable", 409, false);
    const next = normalizeTransaction({ ...current, ...patch, flowId }, this.now());
    this.storage.set(this.transactionKey(flowId), JSON.stringify(next));
    return next;
  }

  rekey(flowId: string, nextFlowId: string): PkceTransaction {
    const current = this.load(flowId);
    if (current === null) throw new AuthError("invalid_oidc_transaction", "OIDC transaction is unavailable", 409, false);
    const next = normalizeTransaction({ ...current, flowId: nextFlowId }, this.now());
    const nextKey = this.transactionKey(nextFlowId);
    if (this.storage.get(nextKey) !== undefined) throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
    this.removeRaw(flowId, this.transactionKey(flowId));
    this.storage.set(nextKey, JSON.stringify(next));
    const index = this.readIndex();
    index[next.flowId] = next.createdAt;
    this.storage.set(this.indexKey, JSON.stringify(index));
    return next;
  }

  consume(flowId?: string): PkceTransaction | null {
    const resolvedFlowId = flowId ?? this.findFlowId();
    if (resolvedFlowId === null) return null;
    const key = this.transactionKey(resolvedFlowId);
    const raw = this.storage.get(key) ?? this.readLegacyRaw(resolvedFlowId);
    if (raw === undefined || raw.length === 0) return null;
    this.removeRaw(resolvedFlowId, key);
    try {
      const transaction = normalizeTransaction(JSON.parse(raw) as unknown, this.now());
      if (transaction.flowId !== resolvedFlowId) return null;
      return transaction;
    } catch {
      return null;
    }
  }

  loadByServerReference(reference: string): PkceTransaction | null {
    const normalized = readServerReference(reference);
    for (const flowId of this.readIndexKeys()) {
      const candidate = this.load(flowId);
      if (candidate?.serverFlowId === normalized || candidate?.serverTransactionId === normalized) return candidate;
    }
    return null;
  }

  loadByState(state: string): PkceTransaction | null {
    const normalizedState = readBase64Url(state, 16, 512);
    let selected: PkceTransaction | null = null;
    for (const flowId of this.readIndexKeys()) {
      const candidate = this.load(flowId);
      if (candidate?.state === normalizedState && (selected === null || candidate.createdAt > selected.createdAt)) selected = candidate;
    }
    return selected;
  }

  consumeAtomic(flowId: string): PkceTransaction | null {
    return this.consume(flowId);
  }

  consumeByState(state: string): PkceTransaction | null {
    const candidate = this.loadByState(state);
    return candidate === null ? null : this.consume(candidate.flowId);
  }

  clear(flowId?: string): void {
    if (flowId !== undefined) {
      const resolved = assertFlowId(flowId);
      this.removeRaw(resolved, this.transactionKey(resolved));
      return;
    }
    for (const key of this.readIndexKeys()) this.removeRaw(key, this.transactionKey(key));
    this.storage.remove(this.indexKey);
    this.storage.remove(this.keyPrefix);
  }

  private transactionKey(flowId: string): string {
    return `${this.keyPrefix}.${assertFlowId(flowId)}`;
  }

  private findFlowId(): string | null {
    const keys = this.readIndexKeys();
    if (keys.length === 0) return null;
    let selected: { flowId: string; createdAt: number } | undefined;
    for (const flowId of keys) {
      const transaction = this.load(flowId);
      if (transaction === null) continue;
      if (selected === undefined || transaction.createdAt > selected.createdAt) selected = { flowId, createdAt: transaction.createdAt };
    }
    return selected?.flowId ?? null;
  }

  private readIndexKeys(): string[] {
    const raw = this.storage.get(this.indexKey);
    if (raw === undefined || raw.length === 0) return [];
    try {
      const value = JSON.parse(raw) as unknown;
      if (!isRecord(value)) return [];
      return Object.keys(value).filter((key) => isFlowId(key));
    } catch {
      return [];
    }
  }

  private readIndex(): Record<string, number> {
    const raw = this.storage.get(this.indexKey);
    if (raw === undefined || raw.length === 0) return {};
    try {
      const value = JSON.parse(raw) as unknown;
      if (!isRecord(value)) return {};
      const result: Record<string, number> = {};
      for (const [key, createdAt] of Object.entries(value)) {
        if (isFlowId(key) && typeof createdAt === "number" && Number.isSafeInteger(createdAt) && createdAt >= 0) result[key] = createdAt;
      }
      return result;
    } catch {
      return {};
    }
  }

  private readLegacyRaw(flowId: string): string | undefined {
    const raw = this.storage.get(this.keyPrefix);
    if (raw === undefined || raw.length === 0) return undefined;
    try {
      const value = JSON.parse(raw) as unknown;
      return isRecord(value) && (value.flowId === undefined || value.flowId === flowId) ? raw : undefined;
    } catch {
      return undefined;
    }
  }

  private removeRaw(flowId: string, key: string): void {
    this.storage.remove(key);
    const index = this.readIndex();
    delete index[flowId];
    if (Object.keys(index).length === 0) this.storage.remove(this.indexKey);
    else this.storage.set(this.indexKey, JSON.stringify(index));
    if (this.storage.get(this.keyPrefix) !== undefined) this.storage.remove(this.keyPrefix);
  }
}

export function getOidcTransactionStorageKey(flowId: string, prefix = OIDC_TRANSACTION_STORAGE_KEY): string {
  return `${prefix}.${assertFlowId(flowId)}`;
}

export function assertSafeRedirectUri(value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || /[\u0000-\u001f\u007f\s\\]/u.test(value)) {
    throw new AuthError("invalid_oidc_transaction", "OIDC redirect URI is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AuthError("invalid_oidc_transaction", "OIDC redirect URI is invalid");
  }
  if (parsed.username !== "" || parsed.password !== "" || parsed.hash !== "") {
    throw new AuthError("invalid_oidc_transaction", "OIDC redirect URI is invalid");
  }
  if (parsed.protocol === "https:") {
    if (parsed.hostname.length === 0 || isLoopbackHost(parsed.hostname)) {
      throw new AuthError("invalid_oidc_transaction", "OIDC redirect URI is invalid");
    }
    return value;
  }
  if (parsed.protocol === "http:") {
    if (!isLoopbackHost(parsed.hostname)) {
      throw new AuthError("invalid_oidc_transaction", "OIDC redirect URI is invalid");
    }
    return value;
  }
  const blockedProtocols = new Set(["data:", "file:", "javascript:", "vbscript:"]);
  if (
    blockedProtocols.has(parsed.protocol) ||
    !/^[a-z][a-z0-9+.-]*:/u.test(value) ||
    value.startsWith(`${parsed.protocol}//`) ||
    !value.slice(parsed.protocol.length).startsWith("/") ||
    value.slice(parsed.protocol.length).startsWith("//") ||
    !parsed.pathname.startsWith("/")
  ) {
    throw new AuthError("invalid_oidc_transaction", "OIDC redirect URI is invalid");
  }
  return value;
}

export function normalizeTransaction(value: unknown, now: number): PkceTransaction {
  if (!isRecord(value)) throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
  const state = readBase64Url(value.state, 32, 512);
  const flowId = value.flowId === undefined ? state : readFlowId(value.flowId);
  const nonce = readBase64Url(value.nonce, 32, 512);
  const codeVerifier = readBase64Url(value.codeVerifier, 43, 128);
  const codeChallenge = readBase64Url(value.codeChallenge, 43, 128);
  const redirectUri = assertSafeRedirectUri(readText(value.redirectUri, 2048));
  const origin = normalizeTransactionOrigin(value.origin === undefined ? originFromRedirectUri(redirectUri) : value.origin);
  const clientType = normalizeClientType(value.clientType ?? "web");
  const startGeneration = normalizeCounter(value.startGeneration ?? 0);
  const attempt = normalizeAttempt(value.attempt ?? 1);
  const serverFlowId = value.serverFlowId === undefined ? undefined : readServerReference(value.serverFlowId);
  const serverTransactionId = value.serverTransactionId === undefined ? undefined : readServerReference(value.serverTransactionId);
  const createdAt = value.createdAt;
  if (!Number.isSafeInteger(createdAt) || (createdAt as number) < 0) {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
  }
  const age = now - (createdAt as number);
  if (age < -60000 || age > MAX_OIDC_TRANSACTION_AGE_MS) {
    throw new AuthError("oidc_transaction_expired", "OIDC transaction has expired");
  }
  return {
    flowId,
    state,
    nonce,
    codeVerifier,
    codeChallenge,
    redirectUri,
    origin,
    clientType,
    startGeneration,
    attempt,
    ...(serverFlowId === undefined ? {} : { serverFlowId }),
    ...(serverTransactionId === undefined ? {} : { serverTransactionId }),
    createdAt: createdAt as number,
  };
}

function normalizeTransactionOrigin(value: unknown): string {
  if (typeof value !== "string") throw new AuthError("invalid_oidc_transaction", "OIDC transaction origin is invalid");
  try {
    return normalizeOrigin(value);
  } catch {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction origin is invalid");
  }
}

function normalizeClientType(value: unknown): OidcTransactionClientType {
  if (value === "web" || value === "native" || value === "webview") return value;
  throw new AuthError("invalid_oidc_transaction", "OIDC transaction client type is invalid");
}

function originFromRedirectUri(value: string): string {
  try {
    const origin = new URL(value).origin;
    if (origin === "null") throw new Error("invalid");
    return normalizeOrigin(origin);
  } catch {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction origin is invalid");
  }
}

function assertFlowId(value: string): string {
  return readFlowId(value);
}

function readFlowId(value: unknown): string {
  const normalized = readText(value, 128);
  if (!/^[A-Za-z0-9_-]+$/u.test(normalized) || normalized.length < 16 || /(?:token|secret|authorization|session[_-]?key|refresh|access|id[_-]?token|code)/iu.test(normalized)) {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction flow ID is invalid");
  }
  return normalized;
}

function readServerReference(value: unknown): string {
  const normalized = readText(value, 512);
  if (normalized.length < 8 || !/^[A-Za-z0-9._~-]+$/u.test(normalized) || /(?:token|secret|authorization|session[_-]?key|refresh|access|id[_-]?token|code|state)/iu.test(normalized)) {
    throw new AuthError("invalid_oidc_transaction", "OIDC server reference is invalid");
  }
  return normalized;
}

function isFlowId(value: string): boolean {
  try {
    readFlowId(value);
    return true;
  } catch {
    return false;
  }
}

function secureRandomBytes(length: number): Uint8Array {
  const cryptoValue = (globalThis as { crypto?: { getRandomValues?: (value: Uint8Array) => Uint8Array } }).crypto;
  if (typeof cryptoValue?.getRandomValues !== "function") {
    throw new AuthError("invalid_oidc_transaction", "Secure random generation is unavailable");
  }
  return cryptoValue.getRandomValues(new Uint8Array(length));
}

async function secureSha256(value: Uint8Array): Promise<ArrayBuffer> {
  const cryptoValue = (globalThis as {
    crypto?: { subtle?: { digest?: (algorithm: string, data: BufferSource) => Promise<ArrayBuffer> } };
  }).crypto;
  if (typeof cryptoValue?.subtle?.digest !== "function") {
    throw new AuthError("invalid_oidc_transaction", "Secure digest generation is unavailable");
  }
  return cryptoValue.subtle.digest("SHA-256", value as BufferSource);
}

function utf8ToBytes(value: string): Uint8Array {
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        const combined = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        bytes.push(0xf0 | (combined >> 18), 0x80 | ((combined >> 12) & 0x3f), 0x80 | ((combined >> 6) & 0x3f), 0x80 | (combined & 0x3f));
        index += 1;
      } else {
        bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      }
    } else {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  return new Uint8Array(bytes);
}

function encodeBase64Url(value: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let output = "";
  for (let index = 0; index < value.length; index += 3) {
    const first = value[index];
    const second = value[index + 1];
    const third = value[index + 2];
    output += alphabet[first >> 2];
    output += alphabet[((first & 3) << 4) | ((second ?? 0) >> 4)];
    output += second === undefined ? "" : alphabet[((second & 15) << 2) | ((third ?? 0) >> 6)];
    output += third === undefined ? "" : alphabet[third & 63];
  }
  return output;
}

function assertByteLength(value: Uint8Array, length: number): Uint8Array {
  if (value.length !== length) {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
  }
  return value;
}

function assertBase64Url(value: string, min: number, max: number): void {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length < min || value.length > max) {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
  }
}

function readBase64Url(value: unknown, min: number, max: number): string {
  const normalized = readText(value, max);
  assertBase64Url(normalized, min, max);
  return normalized;
}

function readText(value: unknown, max: number): string {
  if (typeof value !== "string") {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > max || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new AuthError("invalid_oidc_transaction", "OIDC transaction is invalid");
  }
  return normalized;
}

function normalizeFlowFence(value: unknown): OidcFlowFence {
  if (!isRecord(value)) throw new AuthError("invalid_oidc_transaction", "OIDC flow fence is invalid", 409, false);
  const generation = value.generation;
  const attempt = value.attempt;
  if (
    typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 0 ||
    typeof attempt !== "number" || !Number.isSafeInteger(attempt) || attempt < 1 ||
    (generation === 0 && attempt !== 1)
  ) {
    throw new AuthError("invalid_oidc_transaction", "OIDC flow fence is invalid", 409, false);
  }
  return { generation, attempt };
}

function normalizeCounter(value: unknown): number {
  if (value === undefined) return 0;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new AuthError("invalid_oidc_transaction", "OIDC transaction generation is invalid");
  return value;
}

function normalizeAttempt(value: unknown): number {
  if (value === undefined) return 1;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) throw new AuthError("invalid_oidc_transaction", "OIDC transaction attempt is invalid");
  return value;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
