import type { OpenPlatformPage, OpenPlatformPageQuery } from "./types.js";
import { OpenPlatformProtocolError } from "./errors.js";

export function normalizeOpenPlatformPage<T>(value: unknown): OpenPlatformPage<T> {
  if (Array.isArray(value)) {
    return {
      items: [...value] as T[],
      hasMore: false,
      total: value.length,
    };
  }
  if (!isRecord(value)) {
    throw new OpenPlatformProtocolError();
  }
  const source = isRecord(value.data) && !Array.isArray(value.data) && "items" in value.data
    ? value.data
    : isRecord(value.result) && !Array.isArray(value.result) && "items" in value.result
      ? value.result
      : value;
  const rawItems = Array.isArray(source)
    ? source
    : Array.isArray(source.items)
      ? source.items
      : Array.isArray(source.data)
        ? source.data
        : undefined;
  if (rawItems === undefined) {
    throw new OpenPlatformProtocolError();
  }
  const nextCursor = safeCursor(source.nextCursor);
  const previousCursor = safeCursor(source.previousCursor);
  const hasMore = typeof source.hasMore === "boolean"
    ? source.hasMore
    : nextCursor !== undefined;
  const total = typeof source.total === "number" && Number.isFinite(source.total) && source.total >= 0
    ? source.total
    : undefined;
  return {
    items: [...rawItems] as T[],
    ...(nextCursor === undefined ? {} : { nextCursor }),
    ...(previousCursor === undefined ? {} : { previousCursor }),
    hasMore,
    ...(total === undefined ? {} : { total }),
  };
}

export interface CollectOpenPlatformPagesOptions {
  readonly maxPages?: number;
}

export async function collectOpenPlatformPages<T>(
  load: (cursor?: string) => Promise<OpenPlatformPage<T>>,
  options: CollectOpenPlatformPagesOptions = {},
): Promise<T[]> {
  const maxPages = options.maxPages ?? 1000;
  if (!Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 10000) {
    throw new OpenPlatformProtocolError();
  }
  const items: T[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let pageIndex = 0; pageIndex < maxPages; pageIndex += 1) {
    const page = normalizeOpenPlatformPage<T>(await load(cursor));
    items.push(...page.items);
    if (!page.hasMore || page.nextCursor === undefined || page.nextCursor.length === 0) break;
    if (seen.has(page.nextCursor)) throw new OpenPlatformProtocolError();
    seen.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  return items;
}

export function normalizeOpenPlatformPageQuery(
  query: OpenPlatformPageQuery = {},
): Record<string, string> {
  if (!isRecord(query)) throw new OpenPlatformProtocolError();
  const output: Record<string, string> = {};
  if (query.cursor !== undefined) {
    const cursor = safeCursor(query.cursor);
    if (cursor === undefined) throw new OpenPlatformProtocolError();
    output.cursor = cursor;
  }
  const rawLimit: unknown = query.limit ?? query.pageSize;
  if (rawLimit !== undefined) {
    if (typeof rawLimit !== "number" && typeof rawLimit !== "string") throw new OpenPlatformProtocolError();
    const normalized = typeof rawLimit === "number" ? String(rawLimit) : rawLimit.trim();
    if (!/^[1-9][0-9]{0,2}$/u.test(normalized)) throw new OpenPlatformProtocolError();
    output.limit = normalized;
  }
  return output;
}

function safeCursor(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 2048 ||
    /[\u0000-\u001f\u007f\s]/u.test(normalized)
  ) {
    throw new OpenPlatformProtocolError();
  }
  return normalized;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
