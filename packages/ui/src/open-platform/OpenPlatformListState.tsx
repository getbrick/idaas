import type { OpenPlatformErrorValue, OpenPlatformListBaseProps } from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
} from "./theme.js";
import { EmptyState, ErrorState, LoadingState } from "./states.js";

export interface OpenPlatformListStateProps extends OpenPlatformListBaseProps {
  loading: boolean;
  empty: boolean;
  error?: OpenPlatformErrorValue;
  colSpan: number;
}

export function OpenPlatformListState({
  loading,
  empty,
  error,
  colSpan,
  emptyTitle,
  emptyMessage,
  errorTitle,
  loadingLabel,
  retryLabel,
  onRetry,
  className,
  ...namespaceProps
}: OpenPlatformListStateProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const safeColSpan = Number.isFinite(colSpan) ? Math.max(1, Math.floor(colSpan)) : 1;
  const content = error != null ? (
    <ErrorState
      error={error}
      title={errorTitle}
      retryLabel={retryLabel}
      onRetry={onRetry}
      classNamespace={namespace}
    />
  ) : loading ? (
    <LoadingState label={loadingLabel} classNamespace={namespace} />
  ) : empty ? (
    <EmptyState title={emptyTitle} message={emptyMessage ?? "No records are available."} classNamespace={namespace} />
  ) : null;
  if (!content) return null;
  return (
    <tr className={openPlatformClassNames(openPlatformClassName(namespace, "list-state"), className)}>
      <td colSpan={safeColSpan}>{content}</td>
    </tr>
  );
}

export const OpenPlatformTableState = OpenPlatformListState;
