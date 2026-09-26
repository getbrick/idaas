export const DEFAULT_OPEN_PLATFORM_CLASS_NAMESPACE = "gb-open-platform";

const SAFE_CLASS_TOKEN = /^[A-Za-z_][A-Za-z0-9_-]*$/;
const URL_SCHEME = /^[a-z][a-z\d+.-]*:/iu;
const HTML_ENTITY = /&(?:#x[0-9a-f]+|#\d+|[a-z][a-z\d]+);/iu;
const UNSAFE_ENCODED_URL_CHARACTER = /%(?:00|0[1-9a-f]|1[0-9a-f]|2f|5c|5e|7f)/iu;
const EXTERNAL_HTTPS_URL = /^https:\/\//iu;
const APPROVED_EXTERNAL_PORTS = new Set(["", "443"]);

export interface OpenPlatformTheme {
  classNamespace?: string;
  classNamePrefix?: string;
}

export interface OpenPlatformClassNamespaceProps {
  classNamespace?: string;
  classNamePrefix?: string;
  theme?: OpenPlatformTheme;
  className?: string;
}

export function sanitizeOpenPlatformClassNamespace(namespace?: string): string {
  return namespace && SAFE_CLASS_TOKEN.test(namespace) ? namespace : DEFAULT_OPEN_PLATFORM_CLASS_NAMESPACE;
}

export function resolveOpenPlatformClassNamespace(props: OpenPlatformClassNamespaceProps): string {
  return sanitizeOpenPlatformClassNamespace(
    props.classNamespace ?? props.classNamePrefix ?? props.theme?.classNamespace ?? props.theme?.classNamePrefix,
  );
}

export function sanitizeOpenPlatformClassName(value?: string): string | undefined {
  if (!value) return undefined;
  const tokens = value.split(/\s+/).filter((token) => SAFE_CLASS_TOKEN.test(token));
  return tokens.length > 0 ? tokens.join(" ") : undefined;
}

export function openPlatformClassName(namespace: string | undefined, ...parts: string[]): string {
  const safeNamespace = sanitizeOpenPlatformClassNamespace(namespace);
  const safeParts = parts
    .map((part) => sanitizeOpenPlatformClassName(part))
    .filter((part): part is string => Boolean(part));
  return [safeNamespace, ...safeParts].join("__");
}

export function openPlatformClassNames(...values: Array<string | undefined>): string | undefined {
  const tokens = values
    .flatMap((value) => value?.split(/\s+/) ?? [])
    .filter((token) => SAFE_CLASS_TOKEN.test(token));
  return tokens.length > 0 ? tokens.join(" ") : undefined;
}

export function sanitizeOpenPlatformHref(href: string): string | undefined {
  const value = normalizeHref(href);
  if (!value || value.startsWith("//")) return undefined;
  return URL_SCHEME.test(value) ? sanitizeOpenPlatformExternalHref(value) : sanitizeOpenPlatformInternalHref(value);
}

export function sanitizeOpenPlatformInternalHref(href: string): string | undefined {
  const value = normalizeHref(href);
  if (!value || value.startsWith("//") || URL_SCHEME.test(value)) return undefined;
  if (/(?:[?&])(?:[^#=&]*(?:secret|token|password|private[-_]?key|credential|authorization|cookie|signature|bearer)[^#=&]*)=/iu.test(value)) return undefined;
  return value;
}

export function sanitizeOpenPlatformExternalHref(href: string): string | undefined {
  const value = normalizeHref(href);
  if (!value || !EXTERNAL_HTTPS_URL.test(value)) return undefined;
  const authorityStart = value.indexOf("//") + 2;
  const authorityEndCandidates = [value.indexOf("/", authorityStart), value.indexOf("?", authorityStart), value.indexOf("#", authorityStart)]
    .filter((index) => index >= 0);
  const authorityEnd = authorityEndCandidates.length > 0 ? Math.min(...authorityEndCandidates) : value.length;
  const authority = value.slice(authorityStart, authorityEnd);
  if (authority.includes("@")) return undefined;
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol.toLowerCase() !== "https:" ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      !APPROVED_EXTERNAL_PORTS.has(parsed.port)
    ) return undefined;
    for (const [key, item] of parsed.searchParams) {
      if (/(?:secret|token|password|private[-_]?key|credential|authorization|cookie|signature|bearer)/iu.test(`${key} ${item}`)) return undefined;
    }
    return parsed.toString();
  } catch {
    return undefined;
  }
}

function normalizeHref(href: string): string | undefined {
  if (typeof href !== "string") return undefined;
  const value = href.trim();
  if (
    !value ||
    /[\s\\]/u.test(value) ||
    HTML_ENTITY.test(value) ||
    UNSAFE_ENCODED_URL_CHARACTER.test(value)
  ) return undefined;
  return value;
}
