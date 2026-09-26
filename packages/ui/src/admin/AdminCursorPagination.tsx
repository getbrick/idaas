import type { AdminPagination } from "./contracts.js";
import { getAdminNonNegativeInteger, getAdminPositiveInteger } from "./listUtils.js";
import {
  adminClassName,
  adminClassNames,
  resolveAdminClassNamespace,
  type AdminClassNamespaceProps,
} from "./theme.js";

export interface AdminCursorPaginationProps extends AdminClassNamespaceProps {
  block?: string;
  pagination?: AdminPagination;
  cursor?: string;
  nextCursor?: string;
  previousCursor?: string;
  hasMore?: boolean;
  page?: number;
  pageSize?: number;
  total?: number;
  itemCount?: number;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  onCursorChange?: (cursor?: string) => void;
  onNext?: () => void;
  onPrevious?: () => void;
  onLoadMore?: () => void;
  hasNext?: boolean;
  hasPrevious?: boolean;
  onPageChange?: (page: number) => void;
  paginationLabel?: string;
  previousLabel?: string;
  nextLabel?: string;
}

export function AdminCursorPagination({
  block = "cursor-pagination",
  pagination,
  cursor: cursorProp,
  nextCursor: nextCursorProp,
  previousCursor: previousCursorProp,
  hasMore: hasMoreProp,
  page: pageProp,
  pageSize: pageSizeProp,
  total: totalProp,
  itemCount,
  hasNextPage: hasNextPageProp,
  hasPreviousPage: hasPreviousPageProp,
  onCursorChange: onCursorChangeProp,
  onNext: onNextProp,
  onPrevious: onPreviousProp,
  onLoadMore: onLoadMoreProp,
  hasNext: hasNextProp,
  hasPrevious: hasPreviousProp,
  onPageChange: onPageChangeProp,
  paginationLabel,
  previousLabel,
  nextLabel,
  className,
  ...namespaceProps
}: AdminCursorPaginationProps) {
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const cursor = cursorProp ?? pagination?.cursor;
  const nextCursor = nextCursorProp ?? pagination?.nextCursor;
  const previousCursor = previousCursorProp ?? pagination?.previousCursor;
  const hasMore = hasMoreProp ?? pagination?.hasMore;
  const page = getAdminPositiveInteger(pageProp ?? pagination?.page, 1);
  const pageSize = getAdminPositiveInteger(pageSizeProp ?? pagination?.pageSize, itemCount || 1);
  const total = getAdminNonNegativeInteger(totalProp ?? pagination?.total, itemCount ?? 0);
  const hasNextPage = hasNextPageProp ?? pagination?.hasNextPage;
  const hasPreviousPage = hasPreviousPageProp ?? pagination?.hasPreviousPage;
  const onCursorChange = onCursorChangeProp ?? pagination?.onCursorChange;
  const onNext = onNextProp ?? pagination?.onNext;
  const onPrevious = onPreviousProp ?? pagination?.onPrevious;
  const onLoadMore = onLoadMoreProp ?? pagination?.onLoadMore;
  const hasNext = hasNextProp ?? pagination?.hasNext;
  const hasPrevious = hasPreviousProp ?? pagination?.hasPrevious;
  const onPageChange = onPageChangeProp ?? pagination?.onPageChange;
  const cursorMode =
    cursor !== undefined ||
    nextCursor !== undefined ||
    previousCursor !== undefined ||
    hasMore !== undefined ||
    onCursorChange !== undefined ||
    onNext !== undefined ||
    onPrevious !== undefined ||
    onLoadMore !== undefined ||
    hasNext !== undefined ||
    hasPrevious !== undefined;
  const pageMode =
    pageProp !== undefined ||
    pageSizeProp !== undefined ||
    totalProp !== undefined ||
    hasNextPageProp !== undefined ||
    hasPreviousPageProp !== undefined ||
    onPageChange !== undefined;
  if (!cursorMode && !pageMode && pagination === undefined) return null;

  const accessiblePaginationLabel = paginationLabel?.trim() || "Pagination";
  const accessiblePreviousLabel = previousLabel?.trim() || "Previous";
  const accessibleNextLabel = nextLabel?.trim() || "Next";
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const canPrevious = cursorMode
    ? hasPrevious ?? (cursor !== undefined || previousCursor !== undefined)
    : hasPrevious ?? hasPreviousPage ?? page > 1;
  const canNext = cursorMode
    ? (nextCursor !== undefined || onNext !== undefined || onLoadMore !== undefined) && (hasMore ?? hasNext ?? true) !== false
    : hasNextPage ?? page < pageCount;
  const status = cursorMode ? "Cursor page" : `Page ${page} of ${pageCount}`;

  return (
    <nav
      className={adminClassNames(adminClassName(namespace, block, "pagination"), className)}
      aria-label={accessiblePaginationLabel}
      data-pagination-mode={cursorMode ? "cursor" : "page"}
    >
      <button
        className={adminClassName(namespace, block, "previous-page")}
        type="button"
        disabled={!canPrevious || (cursorMode ? !onCursorChange && !onPrevious : !onPageChange)}
        onClick={() => {
          if (cursorMode) {
            if (onPrevious) onPrevious();
            else onCursorChange?.(previousCursor);
          } else onPageChange?.(page - 1);
        }}
      >
        {accessiblePreviousLabel}
      </button>
      <span
        className={adminClassName(namespace, block, "page-status")}
        aria-live="polite"
      >
        {status}
        {cursorMode && total > 0 ? ` · ${total} total` : ""}
      </span>
      <button
        className={adminClassName(namespace, block, "next-page")}
        type="button"
        disabled={!canNext || (cursorMode ? !onCursorChange && !onNext && !onLoadMore : !onPageChange)}
        onClick={() => {
          if (cursorMode) {
            if (onNext) onNext();
            else if (onLoadMore) onLoadMore();
            else onCursorChange?.(nextCursor);
          } else onPageChange?.(page + 1);
        }}
      >
        {accessibleNextLabel}
      </button>
    </nav>
  );
}

export const AdminPaginationControls = AdminCursorPagination;
