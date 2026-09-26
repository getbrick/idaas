export const DEFAULT_ADMIN_CLASS_NAMESPACE = "gb-admin";

const SAFE_CLASS_TOKEN = /^[A-Za-z_][A-Za-z0-9_-]*$/;

export interface AdminTheme {
  classNamespace?: string;
  classNamePrefix?: string;
}

export interface AdminClassNamespaceProps {
  classNamespace?: string;
  classNamePrefix?: string;
  theme?: AdminTheme;
  className?: string;
}

export function sanitizeAdminClassNamespace(namespace?: string): string {
  return namespace && SAFE_CLASS_TOKEN.test(namespace) ? namespace : DEFAULT_ADMIN_CLASS_NAMESPACE;
}

export function resolveAdminClassNamespace(props: AdminClassNamespaceProps): string {
  return sanitizeAdminClassNamespace(
    props.classNamespace ?? props.classNamePrefix ?? props.theme?.classNamespace ?? props.theme?.classNamePrefix,
  );
}

export function sanitizeAdminClassName(value?: string): string | undefined {
  if (!value) return undefined;
  const tokens = value.split(/\s+/).filter((token) => SAFE_CLASS_TOKEN.test(token));
  return tokens.length > 0 ? tokens.join(" ") : undefined;
}

export function adminClassName(namespace: string | undefined, ...parts: string[]): string {
  const safeNamespace = sanitizeAdminClassNamespace(namespace);
  const safeParts = parts
    .map((part) => sanitizeAdminClassName(part))
    .filter((part): part is string => Boolean(part));
  return [safeNamespace, ...safeParts].join("__");
}

export function adminClassNames(...values: Array<string | undefined>): string | undefined {
  const tokens = values
    .flatMap((value) => value?.split(/\s+/) ?? [])
    .filter((token) => SAFE_CLASS_TOKEN.test(token));
  return tokens.length > 0 ? tokens.join(" ") : undefined;
}

export function sanitizeAdminHref(href: string): string | undefined {
  const value = href.trim();
  if (
    !value ||
    /[\u0000-\u001f\u007f]/.test(value) ||
    /&(?:#x0*(?:3a|58)|colon);/i.test(value) ||
    value.startsWith("//")
  )
    return undefined;
  if (!/^[a-z][a-z\d+.-]*:/i.test(value)) return value;
  try {
    const protocol = new URL(value).protocol.toLowerCase();
    return protocol === "http:" || protocol === "https:" || protocol === "mailto:" || protocol === "tel:"
      ? value
      : undefined;
  } catch {
    return undefined;
  }
}
