import type { AdminErrorValue } from "./contracts.js";
import { adminClassName, adminClassNames, resolveAdminClassNamespace } from "./theme.js";
import { Empty, ErrorState, Loading } from "./states.js";
import type { AdminClassNamespaceProps } from "./theme.js";

export interface AdminListStateProps extends AdminClassNamespaceProps {
  loading: boolean;
  empty: boolean;
  error?: AdminErrorValue;
  colSpan: number;
  emptyTitle?: string;
  emptyMessage?: string;
  errorTitle?: string;
  loadingLabel?: string;
  retryLabel?: string;
  onRetry?: () => void;
}

export function AdminListState({
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
}: AdminListStateProps) {
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const safeColSpan = Number.isFinite(colSpan) ? Math.max(1, Math.floor(colSpan)) : 1;
  const content = error != null ? (
    <ErrorState
      error={error}
      retryLabel={retryLabel}
      onRetry={onRetry}
      classNamespace={namespace}
      title={errorTitle}
    />
  ) : loading ? (
    <Loading classNamespace={namespace} label={loadingLabel} />
  ) : empty ? (
    <Empty
      classNamespace={namespace}
      title={emptyTitle}
      message={emptyMessage ?? "No records are available."}
    />
  ) : null;

  if (!content) return null;
  return (
    <tr className={adminClassNames(adminClassName(namespace, "list-state"), className)}>
      <td colSpan={safeColSpan}>{content}</td>
    </tr>
  );
}
