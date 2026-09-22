export const CORE_MODELS = [
  "user",
  "session",
  "account",
  "verification",
  "twoFactor",
  "organization",
  "member",
  "invitation",
] as const;

export type CoreModel = (typeof CORE_MODELS)[number];

export const DEFAULT_TABLES: Record<CoreModel, string> = {
  user: "user",
  session: "session",
  account: "account",
  verification: "verification",
  twoFactor: "two_factor",
  organization: "organization",
  member: "member",
  invitation: "invitation",
};

export interface TableMapOptions {
  prefix?: string;
  overrides?: Record<string, string>;
}

export function buildTableMap(
  options: TableMapOptions = {},
): Record<CoreModel, string> {
  const prefix = options.prefix ?? "gb_idaas_";
  const overrides = options.overrides ?? {};
  const map = {} as Record<CoreModel, string>;
  for (const model of CORE_MODELS) {
    const override = overrides[model];
    if (override && !/^[a-z][a-z0-9_]*$/.test(override)) {
      throw new Error(`invalid table name override for ${model}: ${override}`);
    }
    map[model] = override ?? `${prefix}${snakeCase(model)}`;
  }
  const seen = new Set<string>();
  for (const model of CORE_MODELS) {
    if (seen.has(map[model])) {
      throw new Error(`duplicate table name: ${map[model]}`);
    }
    seen.add(map[model]);
  }
  return map;
}

function snakeCase(input: string): string {
  return input.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
}
