import type {
  ControlPlaneSession,
  ControlPlaneUser,
} from "./types.js";

export type ControlPlaneMutationStatus = "active" | "disabled" | "unknown";

export function normalizeControlPlaneStatus(value: unknown): ControlPlaneMutationStatus {
  if (value === undefined || value === null || value === "") return "active";
  if (typeof value !== "string") return "unknown";
  const normalized = value.trim().toLowerCase();
  if (normalized === "active") return "active";
  if (normalized === "disabled") return "disabled";
  return "unknown";
}

export function isActiveControlPlaneUser(user: ControlPlaneUser): boolean {
  return normalizeControlPlaneStatus(user.status) === "active";
}

export function isDisabledControlPlaneUser(user: ControlPlaneUser): boolean {
  return normalizeControlPlaneStatus(user.status) === "disabled";
}

export function isActiveControlPlaneSession(session: ControlPlaneSession): boolean {
  return normalizeControlPlaneStatus(session.status) === "active" &&
    (session.revokedAt === undefined || session.revokedAt === null);
}

export function controlPlaneUserRoles(user: ControlPlaneUser): string[] {
  const values: string[] = [];
  addRoleValues(values, user.role);
  addRoleValues(values, user.roles);
  return [...new Set(values)];
}

export function controlPlaneUserHasRole(user: ControlPlaneUser, role: string): boolean {
  const normalized = role.trim().toLowerCase();
  return controlPlaneUserRoles(user).some((value) => value.toLowerCase() === normalized);
}

function addRoleValues(output: string[], value: unknown): void {
  if (typeof value === "string") {
    const normalized = value.trim();
    if (normalized.length > 0) output.push(normalized);
    if (normalized.startsWith("[") || normalized.startsWith("{")) {
      try {
        const parsed: unknown = JSON.parse(normalized);
        if (Array.isArray(parsed)) {
          for (const item of parsed) addRoleValues(output, item);
        }
      } catch {
        return;
      }
    }
    return;
  }
  if (!Array.isArray(value)) return;
  for (const item of value) addRoleValues(output, item);
}
