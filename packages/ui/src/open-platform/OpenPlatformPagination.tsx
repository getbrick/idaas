import type { OpenPlatformPage, OpenPlatformPaginationState } from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  type OpenPlatformClassNamespaceProps,
} from "./theme.js";

export interface OpenPlatformPaginationProps extends OpenPlatformClassNamespaceProps {
  block?: string;
  pagination?: OpenPlatformPaginationState | OpenPlatformPage<unknown>;
  cursor?: string;
  nextCursor?: string;
  previousCursor?: string;
  hasMore?: boolean;
  nextSequence?: number | string;
  previousSequence?: number | string;
  page?: number;
  pageSize?: number;
  total?: number;
  itemCount?: number;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  hasNext?: boolean;
  hasPrevious?: boolean;
  onCursorChange?: (cursor?: string) => void;
  onNext?: () => void;
  onPrevious?: () => void;
  onNextPage?: () => void;
  onPreviousPage?: () => void;
  onLoadMore?: () => void;
  onPageChange?: (page: number) => void;
  paginationLabel?: string;
  previousLabel?: string;
  nextLabel?: string;
}

export function OpenPlatformPagination({
  block = "pagination",
  pagination,
  cursor: cursorProp,
  nextCursor: nextCursorProp,
  previousCursor: previousCursorProp,
  hasMore: hasMoreProp,
  nextSequence: nextSequenceProp,
  previousSequence: previousSequenceProp,
  page: pageProp,
  pageSize: pageSizeProp,
  total: totalProp,
  itemCount = 0,
  hasNextPage: hasNextPageProp,
  hasPreviousPage: hasPreviousPageProp,
  hasNext: hasNextProp,
  hasPrevious: hasPreviousProp,
  onCursorChange: onCursorChangeProp,
  onNext: onNextProp,
  onPrevious: onPreviousProp,
  onNextPage: onNextPageProp,
  onPreviousPage: onPreviousPageProp,
  onLoadMore: onLoadMoreProp,
  onPageChange: onPageChangeProp,
  paginationLabel,
  previousLabel,
  nextLabel,
  className,
  ...namespaceProps
}: OpenPlatformPaginationProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const state = isPaginationState(pagination) ? pagination : undefined;
  const pageState = isPage(pagination) ? pagination : undefined;
  const cursor = cursorProp ?? state?.cursor;
  const nextSequenceToken = safeSequenceToken(nextSequenceProp ?? state?.nextSequence ?? pageState?.nextSequence);
  const previousSequenceToken = safeSequenceToken(previousSequenceProp ?? state?.previousSequence ?? pageState?.previousSequence);
  const nextCursor = nextCursorProp ?? state?.nextCursor ?? pageState?.nextCursor ?? pageState?.next_cursor ?? nextSequenceToken;
  const previousCursor = previousCursorProp ?? state?.previousCursor ?? pageState?.previousCursor ?? pageState?.previous_cursor ?? previousSequenceToken;
  const hasMore = hasMoreProp ?? state?.hasMore ?? pageState?.hasMore ?? pageState?.has_more;
  const page = positiveInteger(pageProp ?? state?.page, 1);
  const pageSize = positiveInteger(pageSizeProp ?? state?.pageSize, itemCount || 1);
  const total = nonNegativeInteger(totalProp ?? state?.total ?? pageState?.total, itemCount);
  const hasNextPage = hasNextPageProp ?? state?.hasNextPage;
  const hasPreviousPage = hasPreviousPageProp ?? state?.hasPreviousPage;
  const hasNext = hasNextProp ?? state?.hasNext;
  const hasPrevious = hasPreviousProp ?? state?.hasPrevious;
  const onCursorChange = onCursorChangeProp ?? state?.onCursorChange;
  const onNext = onNextProp ?? state?.onNext ?? onNextPageProp ?? state?.onNextPage;
  const onPrevious = onPreviousProp ?? state?.onPrevious ?? onPreviousPageProp ?? state?.onPreviousPage;
  const onLoadMore = onLoadMoreProp ?? state?.onLoadMore;
  const onPageChange = onPageChangeProp ?? state?.onPageChange;
  const cursorMode =
    cursor !== undefined ||
    nextCursor !== undefined ||
    previousCursor !== undefined ||
    hasMore !== undefined ||
    hasNext !== undefined ||
    hasPrevious !== undefined ||
    onCursorChange !== undefined ||
    onNext !== undefined ||
    onPrevious !== undefined ||
    onLoadMore !== undefined ||
    nextSequenceProp !== undefined ||
    previousSequenceProp !== undefined;
  const pageMode =
    pageProp !== undefined ||
    pageSizeProp !== undefined ||
    totalProp !== undefined ||
    hasNextPageProp !== undefined ||
    hasPreviousPageProp !== undefined ||
    onPageChange !== undefined ||
    (pageState !== undefined && pageState.items !== undefined);
  if (!cursorMode && !pageMode && pagination === undefined) return null;

  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const canPrevious = cursorMode
    ? hasPrevious ?? hasPreviousPage ?? (cursor !== undefined || previousCursor !== undefined)
    : hasPreviousPage ?? hasPrevious ?? page > 1;
  const canNext = cursorMode
    ? (hasNext ?? hasNextPage ?? hasMore ?? nextCursor !== undefined) !== false && (nextCursor !== undefined || onNext !== undefined || onLoadMore !== undefined)
    : hasNextPage ?? hasNext ?? page < pageCount;
  const mode = cursorMode ? "cursor" : "page";
  const status = cursorMode ? "Cursor page" : `Page ${page} of ${pageCount}`;
  const previousText = safeLabel(previousLabel, "Previous");
  const nextText = safeLabel(nextLabel, "Next");
  const paginationText = safeLabel(paginationLabel, "Pagination");

  return (
    <nav
      className={openPlatformClassNames(openPlatformClassName(namespace, block, "pagination"), className)}
      aria-label={paginationText}
      data-open-platform-pagination={mode}
      data-pagination-mode={mode}
    >
      <button
        className={openPlatformClassName(namespace, block, "previous-page")}
        type="button"
        disabled={!canPrevious || (cursorMode ? !onCursorChange && !onPrevious : !onPageChange)}
        onClick={() => {
          if (cursorMode) {
            if (onPrevious) onPrevious();
            else onCursorChange?.(previousCursor);
          } else onPageChange?.(page - 1);
        }}
      >
        {previousText}
      </button>
      <span className={openPlatformClassName(namespace, block, "page-status")} aria-live="polite">
        {status}
        {cursorMode && total > 0 ? ` · ${total} total` : ""}
      </span>
      <button
        className={openPlatformClassName(namespace, block, "next-page")}
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
        {nextText}
      </button>
    </nav>
  );
}

export const OpenPlatformCursorPagination = OpenPlatformPagination;
export const OperationsPagination = OpenPlatformPagination;

function isPaginationState(value: OpenPlatformPaginationState | OpenPlatformPage<unknown> | undefined): value is OpenPlatformPaginationState {
  return value !== undefined && !("items" in value);
}

function isPage(value: OpenPlatformPaginationState | OpenPlatformPage<unknown> | undefined): value is OpenPlatformPage<unknown> {
  return value !== undefined && "items" in value;
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return value === undefined || !Number.isFinite(value) ? fallback : Math.max(1, Math.floor(value));
}

function nonNegativeInteger(value: number | undefined, fallback: number): number {
  return value === undefined || !Number.isFinite(value) ? fallback : Math.max(0, Math.floor(value));
}

function safeLabel(value: string | undefined, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const normalized = value.trim();
  return normalized.length === 0 || normalized.length > 128 || /[\u0000-\u001f\u007f]/u.test(normalized)
    ? fallback
    : normalized;
}

function safeSequenceToken(value: number | string | undefined): string | undefined {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? String(value) : undefined;
  }
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return /^(?:0|[1-9][0-9]*)$/u.test(normalized) ? normalized : undefined;
}
