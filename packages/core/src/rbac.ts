import type { IdaasConfig } from "./config.js";

export interface RoleDefinition {
  extends?: string[];
  permissions?: string[];
}

export type RoleGraph = Record<string, RoleDefinition>;

export type DataScope = "all" | "own" | "none";

export const DEFAULT_ROLE_GRAPH: RoleGraph = {
  user: { extends: [], permissions: [] },
  admin: { extends: ["user"], permissions: ["*:*"] },
};

export function buildRoleGraph(input: IdaasConfig): RoleGraph {
  const custom = input.rbac?.roles ?? {};
  const graph: RoleGraph = { ...DEFAULT_ROLE_GRAPH };
  for (const [name, def] of Object.entries(custom)) {
    graph[name] = {
      extends: [...(def.extends ?? [])],
      permissions: [...(def.permissions ?? [])],
    };
  }
  for (const [name, def] of Object.entries(graph)) {
    for (const parent of def.extends ?? []) {
      if (!(parent in graph)) {
        throw new Error(`[getbrick-idaas] role "${name}" extends unknown role "${parent}"`);
      }
    }
  }
  for (const name of Object.keys(graph)) {
    detectCycle(graph, name, new Set([name]), []);
  }
  return graph;
}

function detectCycle(graph: RoleGraph, current: string, seen: Set<string>, path: string[]): void {
  for (const parent of graph[current]?.extends ?? []) {
    if (seen.has(parent)) {
      throw new Error(`[getbrick-idaas] role inheritance cycle: ${[...path, parent].join(" -> ")}`);
    }
    seen.add(parent);
    detectCycle(graph, parent, seen, [...path, parent]);
  }
}

export function resolveEffectivePermissions(graph: RoleGraph, role: string): string[] {
  const out = new Set<string>();
  const visit = (name: string) => {
    const def = graph[name];
    if (!def) return;
    for (const permission of def.permissions ?? []) out.add(permission);
    for (const parent of def.extends ?? []) visit(parent);
  };
  visit(role);
  return [...out];
}

export function hasPermission(granted: string[], required: string): boolean {
  return granted.some((permission) => permissionSatisfies(permission, required));
}

export function hasAllPermissions(granted: string[], required: string[]): boolean {
  return required.every((permission) => hasPermission(granted, permission));
}

export function permissionSatisfies(granted: string, required: string): boolean {
  const grantedParts = granted.split(":");
  const requiredParts = required.split(":");
  if (grantedParts.length < 2 || requiredParts.length < 2) return false;
  for (let i = 0; i < 2; i++) {
    if (!segmentMatches(grantedParts[i], requiredParts[i])) return false;
  }
  return scopeSatisfies(grantedParts, requiredParts);
}

function scopeSatisfies(granted: string[], required: string[]): boolean {
  const requiredScope = required[2];
  if (requiredScope === undefined) return true;
  const grantedScope = granted[2] ?? "all";
  if (grantedScope === "all") return true;
  return grantedScope === requiredScope || segmentMatches(grantedScope, requiredScope);
}

function segmentMatches(granted: string, required: string): boolean {
  return granted === "*" || required === "*" || granted === required;
}

export function resolveDataScope(granted: string[], resource: string): DataScope {
  let scope: DataScope = "none";
  for (const permission of granted) {
    const parts = permission.split(":");
    if (parts.length < 2) continue;
    if (!segmentMatches(parts[0], resource) && !segmentMatches(resource, parts[0])) continue;
    const permScope: DataScope = (parts[2] as DataScope) ?? "all";
    if (permScope === "all") return "all";
    if (permScope === "own") scope = "own";
  }
  return scope;
}

export function rolesFromUser(user: Record<string, unknown> | undefined | null): string[] {
  const role = user?.role;
  if (Array.isArray(role)) return role.map(String);
  if (typeof role === "string" && role.length > 0) return [role];
  return ["user"];
}
