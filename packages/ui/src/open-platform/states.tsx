import type { ReactNode } from "react";
import type { OpenPlatformErrorValue } from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  type OpenPlatformClassNamespaceProps,
} from "./theme.js";
import { getOpenPlatformErrorCode, getOpenPlatformErrorMessage, getOpenPlatformPublicText } from "./utils.js";

export interface LoadingStateProps extends OpenPlatformClassNamespaceProps {
  label?: string;
}

export interface ErrorStateProps extends OpenPlatformClassNamespaceProps {
  error?: OpenPlatformErrorValue;
  title?: string;
  retryLabel?: string;
  onRetry?: () => void;
}

export interface EmptyStateProps extends OpenPlatformClassNamespaceProps {
  title?: string;
  message?: string;
  children?: ReactNode;
}

export { getOpenPlatformErrorCode, getOpenPlatformErrorMessage };

export function LoadingState({ label, className, ...namespaceProps }: LoadingStateProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const accessibleLabel = getOpenPlatformPublicText(label, 128) ?? "Loading";
  return (
    <div
      className={openPlatformClassNames(openPlatformClassName(namespace, "state", "loading"), className)}
      data-open-platform-state="loading"
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={accessibleLabel}
    >
      <span className={openPlatformClassName(namespace, "state", "loading-label")}>{accessibleLabel}</span>
    </div>
  );
}

export function ErrorState({
  error,
  title,
  retryLabel,
  onRetry,
  className,
  ...namespaceProps
}: ErrorStateProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const errorCode = getOpenPlatformErrorCode(error);
  const accessibleTitle = getOpenPlatformPublicText(title, 128) ?? "Something went wrong";
  const message = getOpenPlatformErrorMessage(error);
  const accessibleRetryLabel = getOpenPlatformPublicText(retryLabel, 128) ?? "Retry";
  return (
    <div
      className={openPlatformClassNames(openPlatformClassName(namespace, "state", "error"), className)}
      data-open-platform-state="error"
      data-error-code={errorCode}
      role="alert"
      aria-live="assertive"
      aria-atomic="true"
      aria-label={`${accessibleTitle}: ${message}`}
    >
      <strong className={openPlatformClassName(namespace, "state", "error-title")}>{accessibleTitle}</strong>
      <span className={openPlatformClassName(namespace, "state", "error-message")}>{message}</span>
      {onRetry && (
        <button
          className={openPlatformClassName(namespace, "state", "retry")}
          type="button"
          onClick={onRetry}
        >
          {accessibleRetryLabel}
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, message, children, className, ...namespaceProps }: EmptyStateProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const accessibleTitle = getOpenPlatformPublicText(title, 128) ?? "Nothing to show";
  const safeMessage = getOpenPlatformPublicText(message, 512);
  return (
    <div
      className={openPlatformClassNames(openPlatformClassName(namespace, "state", "empty"), className)}
      data-open-platform-state="empty"
      role="status"
      aria-live="polite"
      aria-atomic="true"
      aria-label={accessibleTitle}
    >
      <strong className={openPlatformClassName(namespace, "state", "empty-title")}>{accessibleTitle}</strong>
      {safeMessage && <span className={openPlatformClassName(namespace, "state", "empty-message")}>{safeMessage}</span>}
      {children}
    </div>
  );
}
