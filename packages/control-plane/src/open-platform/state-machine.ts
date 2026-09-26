import {
  invalidStateTransition,
  validationError,
} from "./errors.js";
import {
  OPEN_PLATFORM_CREDENTIAL_STATUSES,
  OPEN_PLATFORM_LIFECYCLE_STATUSES,
  type OpenPlatformCredentialStatus,
  type OpenPlatformLifecycleStatus,
} from "./types.js";

export const OPEN_PLATFORM_LIFECYCLE_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["published", "archived"]),
  published: Object.freeze(["disabled", "archived"]),
  disabled: Object.freeze(["published", "archived"]),
  archived: Object.freeze([]),
} satisfies Readonly<
  Record<
    OpenPlatformLifecycleStatus,
    readonly OpenPlatformLifecycleStatus[]
  >
>);

export const OPEN_PLATFORM_CREDENTIAL_TRANSITIONS = Object.freeze({
  active: Object.freeze(["rotated", "revoked"]),
  rotated: Object.freeze([]),
  revoked: Object.freeze([]),
} satisfies Readonly<
  Record<
    OpenPlatformCredentialStatus,
    readonly OpenPlatformCredentialStatus[]
  >
>);

export function isOpenPlatformLifecycleStatus(
  value: unknown,
): value is OpenPlatformLifecycleStatus {
  return typeof value === "string" &&
    (OPEN_PLATFORM_LIFECYCLE_STATUSES as readonly string[]).includes(value);
}

export function isOpenPlatformCredentialStatus(
  value: unknown,
): value is OpenPlatformCredentialStatus {
  return typeof value === "string" &&
    (OPEN_PLATFORM_CREDENTIAL_STATUSES as readonly string[]).includes(value);
}

export function canTransitionLifecycle(
  from: OpenPlatformLifecycleStatus,
  to: OpenPlatformLifecycleStatus,
): boolean {
  const transitions: readonly OpenPlatformLifecycleStatus[] =
    OPEN_PLATFORM_LIFECYCLE_TRANSITIONS[from];
  return transitions.includes(to);
}

export function assertLifecycleTransition(
  from: OpenPlatformLifecycleStatus,
  to: OpenPlatformLifecycleStatus,
): void {
  if (!canTransitionLifecycle(from, to)) {
    throw invalidStateTransition(from, to);
  }
}

export function allowedLifecycleTransitions(
  from: OpenPlatformLifecycleStatus,
): readonly OpenPlatformLifecycleStatus[] {
  return OPEN_PLATFORM_LIFECYCLE_TRANSITIONS[from];
}

export function canTransitionCredential(
  from: OpenPlatformCredentialStatus,
  to: OpenPlatformCredentialStatus,
): boolean {
  const transitions: readonly OpenPlatformCredentialStatus[] =
    OPEN_PLATFORM_CREDENTIAL_TRANSITIONS[from];
  return transitions.includes(to);
}

export function assertCredentialTransition(
  from: OpenPlatformCredentialStatus,
  to: OpenPlatformCredentialStatus,
): void {
  if (!canTransitionCredential(from, to)) {
    throw invalidStateTransition(from, to);
  }
}

export function assertLifecycleStatus(
  value: unknown,
): asserts value is OpenPlatformLifecycleStatus {
  if (!isOpenPlatformLifecycleStatus(value)) {
    throw validationError("Lifecycle status is invalid", { field: "targetStatus" });
  }
}

export function assertCredentialStatus(
  value: unknown,
): asserts value is OpenPlatformCredentialStatus {
  if (!isOpenPlatformCredentialStatus(value)) {
    throw validationError("Credential status is invalid", { field: "status" });
  }
}
