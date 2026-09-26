import { useId, type ReactNode } from "react";
import { OpenPlatformListState } from "./OpenPlatformListState.js";
import { OpenPlatformPagination } from "./OpenPlatformPagination.js";
import type {
  OpenPlatformAuditEvent,
  OpenPlatformListBaseProps,
  OpenPlatformPage,
  OpenPlatformPaginationState,
} from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
} from "./theme.js";
import {
  getOpenPlatformDate,
  getOpenPlatformPublicText,
  getOpenPlatformSafeAuditMetadata,
  getOpenPlatformSafeText,
  getOpenPlatformStatusText,
} from "./utils.js";

export interface OpenPlatformAuditEventListProps extends OpenPlatformListBaseProps {
  events?: readonly OpenPlatformAuditEvent[];
  items?: readonly OpenPlatformAuditEvent[];
  data?: readonly OpenPlatformAuditEvent[];
  records?: readonly OpenPlatformAuditEvent[];
  pagination?: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformAuditEvent>;
  cursor?: string;
  nextCursor?: string;
  previousCursor?: string;
  hasMore?: boolean;
  page?: number;
  pageSize?: number;
  total?: number;
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
  renderActions?: (event: OpenPlatformAuditEvent) => ReactNode;
  renderDetail?: (event: OpenPlatformAuditEvent) => ReactNode;
  paginationLabel?: string;
  previousLabel?: string;
  nextLabel?: string;
}

export function OpenPlatformAuditEventList({
  events,
  items,
  data,
  records,
  pagination,
  cursor,
  nextCursor,
  previousCursor,
  hasMore,
  page,
  pageSize,
  total,
  hasNextPage,
  hasPreviousPage,
  hasNext,
  hasPrevious,
  onCursorChange,
  onNext,
  onPrevious,
  onNextPage,
  onPreviousPage,
  onLoadMore,
  onPageChange,
  renderActions,
  renderDetail,
  paginationLabel,
  previousLabel,
  nextLabel,
  title,
  caption,
  actions,
  loading,
  isLoading: isLoadingProp,
  error,
  onRetry,
  emptyTitle,
  emptyMessage,
  errorTitle,
  loadingLabel,
  retryLabel,
  className,
  ...namespaceProps
}: OpenPlatformAuditEventListProps) {
  const headingId = useId();
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const isLoading = isLoadingProp ?? loading ?? false;
  const rows = events ?? items ?? data ?? records ?? pageItems(pagination) ?? [];
  const listTitle = getOpenPlatformPublicText(title, 256) ?? "Audit events";
  const tableCaption = typeof caption === "string" ? getOpenPlatformPublicText(caption, 512) ?? listTitle : caption ?? listTitle;
  const hasActions = renderActions !== undefined;
  const columnCount = hasActions ? 8 : 7;
  const hasPagination = pagination !== undefined || cursor !== undefined || nextCursor !== undefined || previousCursor !== undefined || hasMore !== undefined || page !== undefined || pageSize !== undefined || total !== undefined || hasNextPage !== undefined || hasPreviousPage !== undefined || onCursorChange !== undefined || onNext !== undefined || onPrevious !== undefined || onLoadMore !== undefined || onPageChange !== undefined || hasNext !== undefined || hasPrevious !== undefined || onNextPage !== undefined || onPreviousPage !== undefined;

  return (
    <section
      className={openPlatformClassNames(openPlatformClassName(namespace, "open-platform-audit-event-list"), className)}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-open-platform-list="audit-events"
      data-open-platform-resource="audit-events"
    >
      <header className={openPlatformClassName(namespace, "open-platform-audit-event-list", "header")}>
        <h2 id={headingId} className={openPlatformClassName(namespace, "open-platform-audit-event-list", "heading")}>
          {listTitle}
        </h2>
        {actions !== undefined && actions !== null && (
          <div className={openPlatformClassName(namespace, "open-platform-audit-event-list", "actions")}>{actions}</div>
        )}
      </header>
      <table className={openPlatformClassName(namespace, "open-platform-audit-event-list", "table")} aria-busy={isLoading || undefined}>
        <caption className={openPlatformClassName(namespace, "open-platform-audit-event-list", "caption")}>{tableCaption}</caption>
        <thead>
          <tr>
            <th scope="col">Action</th>
            <th scope="col">Actor</th>
            <th scope="col">Target</th>
            <th scope="col">Outcome</th>
            <th scope="col">Occurred</th>
            <th scope="col">Request ID</th>
            <th scope="col">Details</th>
            {hasActions && <th scope="col">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {error != null || isLoading || rows.length === 0 ? (
            <OpenPlatformListState
              classNamespace={namespace}
              loading={isLoading}
              error={error}
              empty={rows.length === 0}
              colSpan={columnCount}
              emptyTitle={emptyTitle}
              emptyMessage={emptyMessage}
              errorTitle={errorTitle}
              loadingLabel={loadingLabel}
              retryLabel={retryLabel}
              onRetry={onRetry}
            />
          ) : (
            rows.map((event, index) => {
              const action = getOpenPlatformSafeText(event.action ?? event.event ?? event.type, 256) ?? "Unknown action";
              const actor = getActorLabel(event);
              const target = getTargetLabel(event);
              const outcome = getOpenPlatformStatusText(event.outcome, "Unknown");
              const occurred = getOpenPlatformDate(event.occurredAt ?? event.occurred_at ?? event.createdAt);
              const requestId = getOpenPlatformSafeText(event.requestId ?? event.request_id, 128);
              return (
                <tr key={event.id || `audit-${index}`} className={openPlatformClassName(namespace, "open-platform-audit-event-list", "row")}>
                  <td className={openPlatformClassName(namespace, "open-platform-audit-event-list", "cell")}>{action}</td>
                  <td className={openPlatformClassName(namespace, "open-platform-audit-event-list", "cell")}>{actor}</td>
                  <td className={openPlatformClassName(namespace, "open-platform-audit-event-list", "cell")}>{target}</td>
                  <td className={openPlatformClassName(namespace, "open-platform-audit-event-list", "cell")}>
                    <span data-audit-outcome={outcome}>{outcome}</span>
                  </td>
                  <td className={openPlatformClassName(namespace, "open-platform-audit-event-list", "cell")}>
                    {occurred.dateTime ? <time dateTime={occurred.dateTime}>{occurred.label}</time> : "—"}
                  </td>
                  <td className={openPlatformClassName(namespace, "open-platform-audit-event-list", "cell")}>{requestId ?? "—"}</td>
                  <td className={openPlatformClassName(namespace, "open-platform-audit-event-list", "cell")}>
                    {renderDetail ? renderDetail(event) : getOpenPlatformSafeAuditMetadata(event)}
                  </td>
                  {hasActions && <td className={openPlatformClassName(namespace, "open-platform-audit-event-list", "cell")}>{renderActions?.(event)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {hasPagination && (
        <OpenPlatformPagination
          block="open-platform-audit-event-list"
          pagination={pagination}
          cursor={cursor}
          nextCursor={nextCursor}
          previousCursor={previousCursor}
          hasMore={hasMore}
          page={page}
          pageSize={pageSize}
          total={total}
          hasNextPage={hasNextPage}
          hasPreviousPage={hasPreviousPage}
          hasNext={hasNext}
          hasPrevious={hasPrevious}
          onCursorChange={onCursorChange}
          onNext={onNext}
          onPrevious={onPrevious}
          onNextPage={onNextPage}
          onPreviousPage={onPreviousPage}
          onLoadMore={onLoadMore}
          onPageChange={onPageChange}
          paginationLabel={paginationLabel}
          previousLabel={previousLabel}
          nextLabel={nextLabel}
          classNamespace={namespace}
        />
      )}
    </section>
  );
}

export const AuditEventList = OpenPlatformAuditEventList;
export const AuditEventsList = OpenPlatformAuditEventList;
export const OpenPlatformAuditEventsList = OpenPlatformAuditEventList;

function getActorLabel(event: OpenPlatformAuditEvent): string {
  if (typeof event.actor === "string") return getOpenPlatformSafeText(event.actor, 256) ?? "Unknown actor";
  return getOpenPlatformSafeText(event.actor?.displayName ?? event.actor?.name ?? event.actor?.email ?? event.actor?.id, 256) ?? "Unknown actor";
}

function getTargetLabel(event: OpenPlatformAuditEvent): string {
  if (typeof event.target === "string") return getOpenPlatformSafeText(event.target, 256) ?? "Unknown target";
  return getOpenPlatformSafeText(event.target?.displayName ?? event.target?.name ?? event.target?.id, 256) ?? "Unknown target";
}

function pageItems(
  pagination: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformAuditEvent> | undefined,
): readonly OpenPlatformAuditEvent[] | undefined {
  return pagination !== undefined && "items" in pagination ? pagination.items : undefined;
}
