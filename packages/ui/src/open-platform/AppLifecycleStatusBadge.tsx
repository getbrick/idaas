import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  type OpenPlatformClassNamespaceProps,
} from "./theme.js";
import type { AppLifecycleStatus, AppLifecycleStatusDescriptor } from "./types.js";
import { getOpenPlatformText } from "./utils.js";

const STATUS_DESCRIPTORS: Record<string, AppLifecycleStatusDescriptor> = {
  draft: { status: "draft", label: "Draft", tone: "neutral" },
  pending: { status: "pending_review", label: "In review", tone: "warning" },
  pending_review: { status: "pending_review", label: "In review", tone: "warning" },
  submitted: { status: "pending_review", label: "In review", tone: "warning" },
  in_review: { status: "pending_review", label: "In review", tone: "warning" },
  active: { status: "active", label: "Active", tone: "success" },
  approved: { status: "active", label: "Active", tone: "success" },
  published: { status: "active", label: "Active", tone: "success" },
  live: { status: "active", label: "Active", tone: "success" },
  disabled: { status: "disabled", label: "Disabled", tone: "warning" },
  inactive: { status: "disabled", label: "Disabled", tone: "warning" },
  suspended: { status: "suspended", label: "Suspended", tone: "danger" },
  rejected: { status: "rejected", label: "Rejected", tone: "danger" },
  archived: { status: "archived", label: "Archived", tone: "neutral" },
  purged: { status: "purged", label: "Purged", tone: "danger" },
};

const UNKNOWN_STATUS: AppLifecycleStatusDescriptor = {
  status: "unknown",
  label: "Unknown",
  tone: "neutral",
};

export interface AppLifecycleStatusBadgeProps extends OpenPlatformClassNamespaceProps {
  status: AppLifecycleStatus;
  label?: string;
  ariaLabel?: string;
}

export function getAppLifecycleStatus(status: unknown): AppLifecycleStatusDescriptor {
  const text = getOpenPlatformText(status, 128);
  if (!text) return UNKNOWN_STATUS;
  const normalized = text.toLowerCase().replace(/[\s-]+/gu, "_");
  return STATUS_DESCRIPTORS[normalized] ?? UNKNOWN_STATUS;
}

export function AppLifecycleStatusBadge({
  status,
  label,
  ariaLabel,
  className,
  ...namespaceProps
}: AppLifecycleStatusBadgeProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const descriptor = getAppLifecycleStatus(status);
  const text = getOpenPlatformText(label, 128) ?? descriptor.label;
  const accessibleLabel = getOpenPlatformText(ariaLabel, 256) ?? `Application status: ${text}`;
  return (
    <span
      className={openPlatformClassNames(openPlatformClassName(namespace, "app-lifecycle-status"), className)}
      data-lifecycle-status={descriptor.status}
      data-status-tone={descriptor.tone}
      aria-label={accessibleLabel}
    >
      {text}
    </span>
  );
}
