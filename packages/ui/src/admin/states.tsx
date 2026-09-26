import type { ReactNode } from "react";
import type { AdminErrorValue } from "./contracts.js";
import {
  adminClassName,
  adminClassNames,
  resolveAdminClassNamespace,
  type AdminClassNamespaceProps,
} from "./theme.js";

export interface LoadingProps extends AdminClassNamespaceProps {
  label?: string;
}

export interface ErrorStateProps extends AdminClassNamespaceProps {
  error?: AdminErrorValue;
  title?: string;
  retryLabel?: string;
  onRetry?: () => void;
}

export interface EmptyProps extends AdminClassNamespaceProps {
  title?: string;
  message?: string;
  children?: ReactNode;
}

export type LoadingStateProps = LoadingProps;

export type ErrorProps = ErrorStateProps;

export function getAdminErrorMessage(error?: AdminErrorValue): string {
  if (typeof error === "string") return safeErrorText(error) ?? "Something went wrong.";
  if (error instanceof Error) return safeErrorText(error.message) ?? "Something went wrong.";
  if (!error || typeof error !== "object") return "Something went wrong.";
  const record = error as Record<string, unknown>;
  const envelope = record.error;
  if (envelope && typeof envelope === "object") {
    const nested = envelope as Record<string, unknown>;
    const message = safeErrorText(nested.message);
    if (message) return message;
  }
  const response = record.response;
  if (response && typeof response === "object") {
    const body = (response as Record<string, unknown>).body;
    if (body && typeof body === "object") {
      const bodyError = (body as Record<string, unknown>).error;
      if (bodyError && typeof bodyError === "object") {
        const message = safeErrorText((bodyError as Record<string, unknown>).message);
        if (message) return message;
      }
    }
  }
  return safeErrorText(record.message) ?? "Something went wrong.";
}

function safeErrorText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 512 ||
    /[\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)
  ) return undefined;
  return normalized;
}

export function Loading({ label = "Loading", className, ...namespaceProps }: LoadingProps) {
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const accessibleLabel = label.trim() || "Loading";
  return (
    <div
      className={adminClassNames(adminClassName(namespace, "state", "loading"), className)}
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={accessibleLabel}
    >
      <span className={adminClassName(namespace, "state", "loading-label")}>{accessibleLabel}</span>
    </div>
  );
}

export function ErrorState({
  error,
  title = "Something went wrong",
  retryLabel = "Retry",
  onRetry,
  className,
  ...namespaceProps
}: ErrorStateProps) {
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const accessibleTitle = title.trim() || "Something went wrong";
  const message = getAdminErrorMessage(error);
  const accessibleRetryLabel = retryLabel.trim() || "Retry";
  return (
    <div
      className={adminClassNames(adminClassName(namespace, "state", "error"), className)}
      role="alert"
      aria-live="assertive"
      aria-atomic="true"
      aria-label={`${accessibleTitle}: ${message}`}
    >
      <strong className={adminClassName(namespace, "state", "error-title")}>{accessibleTitle}</strong>
      <span className={adminClassName(namespace, "state", "error-message")}>{message}</span>
      {onRetry && (
        <button
          className={adminClassName(namespace, "state", "retry")}
          type="button"
          aria-label={accessibleRetryLabel}
          onClick={onRetry}
        >
          {accessibleRetryLabel}
        </button>
      )}
    </div>
  );
}

export function Empty({ title = "Nothing to show", message, children, className, ...namespaceProps }: EmptyProps) {
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const accessibleTitle = title.trim() || "Nothing to show";
  return (
    <div
      className={adminClassNames(adminClassName(namespace, "state", "empty"), className)}
      role="status"
      aria-live="polite"
      aria-label={accessibleTitle}
    >
      <strong className={adminClassName(namespace, "state", "empty-title")}>{accessibleTitle}</strong>
      {message && <span className={adminClassName(namespace, "state", "empty-message")}>{message}</span>}
      {children}
    </div>
  );
}

export const LoadingState = Loading;
export const Error = ErrorState;
export const EmptyState = Empty;
