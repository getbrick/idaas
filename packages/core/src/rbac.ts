import type { IdaasConfig } from "./config.js";

export interface RoleDefinition {
  extends?: string[];
  permissions?: string[];
}

export type RoleGraph = Record<string, RoleDefinition>;

export type DataScope = "all" | "own" | "none";

export const MAX_ROLE_NAME_LENGTH = 128;
export const MAX_PERMISSION_NAME_LENGTH = 256;

const UNSAFE_NAMES = new Set([
  "__proto__",
  "prototype",
  "constructor",
  "toString",
  "valueOf",
  "hasOwnProperty",
  "isPrototypeOf",
  "propertyIsEnumerable",
  "toLocaleString",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const WHITESPACE = /\s/u;

export const DEFAULT_ROLE_GRAPH: RoleGraph = {
  user: { extends: [], permissions: [] },
  admin: { extends: ["user"], permissions: ["*:*"] },
};

export function buildRoleGraph(input: IdaasConfig): RoleGraph {
  const configuredRoles = input?.rbac?.roles;
  if (configuredRoles !== undefined && !isRecord(configuredRoles)) {
    throw new Error("[getbrick-idaas] rbac.roles must be an object");
  }
  if (isRecord(configuredRoles) && hasDangerousPrototype(configuredRoles)) {
    throw new Error("[getbrick-idaas] dangerous role name \"__proto__\" is not allowed");
  }
  const custom = (configuredRoles ?? {}) as Record<string, unknown>;
  const graph: RoleGraph = {};
  for (const [name, definition] of Object.entries(DEFAULT_ROLE_GRAPH)) {
    setGraphEntry(graph, name, cloneRoleDefinition(name, definition));
  }
  for (const [name, definition] of Object.entries(custom)) {
    setGraphEntry(graph, name, cloneRoleDefinition(name, definition));
  }
  for (const [name, definition] of Object.entries(graph)) {
    for (const parent of definition.extends ?? []) {
      if (!hasOwn(graph, parent)) {
        throw new Error(`[getbrick-idaas] role "${name}" extends unknown role "${parent}"`);
      }
    }
  }
  const completed = new Set<string>();
  for (const name of Object.keys(graph)) {
    detectCycle(graph, name, new Set<string>(), completed);
  }
  return graph;
}

function detectCycle(
  graph: RoleGraph,
  current: string,
  active: Set<string>,
  completed: Set<string>,
): void {
  if (completed.has(current)) return;
  if (active.has(current)) {
    throw new Error(`[getbrick-idaas] role inheritance cycle: ${[current, current].join(" -> ")}`);
  }
  active.add(current);
  const stack: Array<{ name: string; index: number }> = [{ name: current, index: 0 }];
  while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    const parents = graph[frame.name]?.extends ?? [];
    if (frame.index >= parents.length) {
      active.delete(frame.name);
      completed.add(frame.name);
      stack.pop();
      continue;
    }
    const parent = parents[frame.index++];
    if (!hasOwn(graph, parent)) {
      throw new Error(`[getbrick-idaas] role "${frame.name}" extends unknown role "${parent}"`);
    }
    if (completed.has(parent)) continue;
    if (active.has(parent)) {
      const path = [...stack.map((entry) => entry.name), parent];
      throw new Error(`[getbrick-idaas] role inheritance cycle: ${path.join(" -> ")}`);
    }
    active.add(parent);
    stack.push({ name: parent, index: 0 });
  }
}

export function resolveEffectivePermissions(graph: RoleGraph, role: string): string[] {
  validateRoleName(role, "role");
  if (!hasOwn(graph, role)) return [];
  const out = new Set<string>();
  const pending: Array<{ name: string; exit: boolean }> = [{ name: role, exit: false }];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const item = pending.pop()!;
    if (item.exit) continue;
    if (visited.has(item.name)) continue;
    visited.add(item.name);
    const rawDefinition = graph[item.name];
    if (!rawDefinition) continue;
    const definition = cloneRoleDefinition(item.name, rawDefinition);
    for (const permission of definition.permissions ?? []) out.add(permission);
    pending.push({ name: item.name, exit: true });
    const parents = definition.extends ?? [];
    for (let index = parents.length - 1; index >= 0; index--) {
      const parent = parents[index];
      if (hasOwn(graph, parent) && !visited.has(parent)) pending.push({ name: parent, exit: false });
    }
  }
  return [...out];
}

export function hasPermission(granted: string[], required: string): boolean {
  return granted.some((permission) => permissionSatisfies(permission, required));
}

export function hasAllPermissions(granted: string[], required: string[]): boolean {
  return required.every((permission) => hasPermission(granted, permission));
}

export function permissionSatisfies(granted: string, required: string): boolean {
  if (!isValidPermission(granted) || !isValidPermission(required)) return false;
  const grantedParts = granted.split(":");
  const requiredParts = required.split(":");
  for (let i = 0; i < 2; i++) {
    if (!segmentMatches(grantedParts[i], requiredParts[i])) return false;
  }
  return scopeSatisfies(grantedParts, requiredParts);
}

function scopeSatisfies(granted: string[], required: string[]): boolean {
  const requiredScope = required[2];
  if (requiredScope === undefined) return true;
  const grantedScope = granted[2] ?? "all";
  if (grantedScope === "all" || grantedScope === "*") return true;
  return grantedScope === requiredScope || segmentMatches(grantedScope, requiredScope);
}

function segmentMatches(granted: string, required: string): boolean {
  return granted === "*" || required === "*" || granted === required;
}

export function resolveDataScope(granted: string[], resource: string): DataScope {
  let scope: DataScope = "none";
  for (const permission of granted) {
    if (!isValidPermission(permission)) continue;
    const parts = permission.split(":");
    if (!segmentMatches(parts[0], resource) && !segmentMatches(resource, parts[0])) continue;
    const permScope = parts[2] ?? "all";
    if (permScope === "all" || permScope === "*") return "all";
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

function cloneRoleDefinition(name: string, value: unknown): RoleDefinition {
  validateRoleName(name, "role");
  if (!isRecord(value)) {
    throw new Error(`[getbrick-idaas] role "${name}" must be an object`);
  }
  const rawParents = value.extends ?? [];
  const rawPermissions = value.permissions ?? [];
  if (!Array.isArray(rawParents) || !Array.isArray(rawPermissions)) {
    throw new Error(`[getbrick-idaas] role "${name}" extends and permissions must be arrays`);
  }
  const parents = rawParents.map((parent) => {
    validateRoleName(parent, "parent role");
    return parent;
  });
  const permissions = rawPermissions.map((permission) => {
    validatePermission(permission, name);
    return permission;
  });
  return { extends: parents, permissions: permissions };
}

function validatePermission(value: unknown, roleName: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`[getbrick-idaas] invalid permission name in role "${roleName}"`);
  }
  if (value.length > MAX_PERMISSION_NAME_LENGTH) {
    throw new Error(`[getbrick-idaas] permission name is too long in role "${roleName}"`);
  }
  if (CONTROL_CHARACTERS.test(value) || WHITESPACE.test(value)) {
    throw new Error(`[getbrick-idaas] invalid permission name in role "${roleName}"`);
  }
  const parts = value.split(":");
  if (parts.length < 2 || parts.length > 3 || parts.some((part) => part.length === 0)) {
    throw new Error(`[getbrick-idaas] invalid permission name "${value}" in role "${roleName}"`);
  }
  for (const part of parts) {
    validatePermissionPart(part, value, roleName);
  }
  if (parts[0].includes("*") && parts[0] !== "*") {
    throw new Error(`[getbrick-idaas] invalid wildcard in permission "${value}"`);
  }
  if (parts[1].includes("*") && parts[1] !== "*") {
    throw new Error(`[getbrick-idaas] invalid wildcard in permission "${value}"`);
  }
}

function validatePermissionPart(part: string, permission: string, roleName: string): void {
  if (part.length > 128 || CONTROL_CHARACTERS.test(part) || WHITESPACE.test(part)) {
    throw new Error(`[getbrick-idaas] invalid permission name "${permission}" in role "${roleName}"`);
  }
  if (UNSAFE_NAMES.has(part.toLowerCase()) || part.toLowerCase().includes("__proto__")) {
    throw new Error(`[getbrick-idaas] dangerous permission name "${permission}"`);
  }
}

function validateRoleName(value: unknown, kind: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`[getbrick-idaas] invalid ${kind} name`);
  }
  if (value.length > MAX_ROLE_NAME_LENGTH) {
    throw new Error(`[getbrick-idaas] ${kind} name is too long`);
  }
  if (CONTROL_CHARACTERS.test(value) || WHITESPACE.test(value) || value.includes("*")) {
    throw new Error(`[getbrick-idaas] invalid ${kind} name "${value}"`);
  }
  const normalized = value.toLowerCase();
  if (UNSAFE_NAMES.has(normalized) || normalized.includes("__proto__")) {
    throw new Error(`[getbrick-idaas] dangerous ${kind} name "${value}"`);
  }
}

function isValidPermission(value: unknown): value is string {
  try {
    validatePermission(value, "runtime");
    return true;
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasDangerousPrototype(value: Record<string, unknown>): boolean {
  if (Object.prototype.hasOwnProperty.call(value, "__proto__")) return true;
  const prototype = Object.getPrototypeOf(value);
  return prototype !== Object.prototype && prototype !== null;
}

function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function setGraphEntry(graph: RoleGraph, name: string, definition: RoleDefinition): void {
  Object.defineProperty(graph, name, {
    configurable: true,
    enumerable: true,
    value: definition,
    writable: true,
  });
}
