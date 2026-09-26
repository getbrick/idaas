import { useId, type ReactNode } from "react";
import { OpenPlatformListState } from "./OpenPlatformListState.js";
import { OpenPlatformPagination } from "./OpenPlatformPagination.js";
import { ErrorState } from "./states.js";
import type {
  OpenPlatformDomainEventRetrySummary,
  OpenPlatformDomainEventSummary,
  OpenPlatformErrorValue,
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
  getOpenPlatformComplianceCount,
  getOpenPlatformDate,
  getOpenPlatformPublicText,
  getOpenPlatformStatusText,
} from "./utils.js";

export interface OutboxStatusListProps extends OpenPlatformListBaseProps {
  events?: readonly OpenPlatformDomainEventSummary[];
  outboxEvents?: readonly OpenPlatformDomainEventSummary[];
  items?: readonly OpenPlatformDomainEventSummary[];
  data?: readonly OpenPlatformDomainEventSummary[];
  records?: readonly OpenPlatformDomainEventSummary[];
  pagination?: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformDomainEventSummary>;
  cursor?: string;
  nextCursor?: string;
  previousCursor?: string;
  hasMore?: boolean;
  nextSequence?: number;
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
  renderActions?: (event: OpenPlatformDomainEventSummary) => ReactNode;
  showHeader?: boolean;
  paginationLabel?: string;
  previousLabel?: string;
  nextLabel?: string;
}

export interface DomainEventMonitorProps extends OutboxStatusListProps {
  onRetryEvents?: () => void;
  retrying?: boolean;
  retrySummary?: OpenPlatformDomainEventRetrySummary | null;
  retryError?: OpenPlatformErrorValue;
  retryLabel?: string;
  retryTitle?: string;
  showRetrySummary?: boolean;
  children?: ReactNode;
}

const OUTBOX_BLOCK = "open-platform-outbox-status-list";
const OUTBOX_COLUMN_COUNT = 8;
const MAX_RETRY_RESULTS = 8;

export function OutboxStatusList({
  events,
  outboxEvents,
  items,
  data,
  records,
  pagination,
  cursor,
  nextCursor,
  previousCursor,
  hasMore,
  nextSequence,
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
  showHeader = true,
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
  paginationLabel,
  previousLabel,
  nextLabel,
  className,
  ...namespaceProps
}: OutboxStatusListProps) {
  const headingId = useId();
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const isLoading = isLoadingProp ?? loading ?? false;
  const rows = events ?? outboxEvents ?? items ?? data ?? records ?? pageItems(pagination) ?? [];
  const listTitle = getOpenPlatformPublicText(title, 256) ?? "Outbox events";
  const tableCaption = typeof caption === "string" ? getOpenPlatformPublicText(caption, 512) ?? listTitle : caption ?? listTitle;
  const hasActions = renderActions !== undefined;
  const columnCount = hasActions ? OUTBOX_COLUMN_COUNT + 1 : OUTBOX_COLUMN_COUNT;
  const hasPagination = pagination !== undefined || cursor !== undefined || nextCursor !== undefined || previousCursor !== undefined || hasMore !== undefined || nextSequence !== undefined || page !== undefined || pageSize !== undefined || total !== undefined || hasNextPage !== undefined || hasPreviousPage !== undefined || onCursorChange !== undefined || onNext !== undefined || onPrevious !== undefined || onLoadMore !== undefined || onPageChange !== undefined || hasNext !== undefined || hasPrevious !== undefined || onNextPage !== undefined || onPreviousPage !== undefined;

  return (
    <section
      className={openPlatformClassNames(openPlatformClassName(namespace, OUTBOX_BLOCK), className)}
      aria-labelledby={showHeader ? headingId : undefined}
      aria-busy={isLoading || undefined}
      data-open-platform-list="domain-events"
      data-open-platform-resource="domain-events"
    >
      {showHeader && (
        <header className={openPlatformClassName(namespace, OUTBOX_BLOCK, "header")}>
          <h2 id={headingId} className={openPlatformClassName(namespace, OUTBOX_BLOCK, "heading")}>
            {listTitle}
          </h2>
          {actions !== undefined && actions !== null && (
            <div className={openPlatformClassName(namespace, OUTBOX_BLOCK, "actions")}>{actions}</div>
          )}
        </header>
      )}
      <table className={openPlatformClassName(namespace, OUTBOX_BLOCK, "table")} aria-busy={isLoading || undefined}>
        <caption className={openPlatformClassName(namespace, OUTBOX_BLOCK, "caption")}>{tableCaption}</caption>
        <thead>
          <tr>
            <th scope="col">Event</th>
            <th scope="col">Type</th>
            <th scope="col">Resource</th>
            <th scope="col">Status</th>
            <th scope="col">Attempt</th>
            <th scope="col">Occurred</th>
            <th scope="col">Next attempt</th>
            <th scope="col">Error</th>
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
              const status = getOpenPlatformStatusText(event.status);
              const attempt = getOpenPlatformComplianceCount(event.attempt) ?? 0;
              const occurredAt = getOpenPlatformDate(event.occurredAt);
              const nextAttemptAt = getOpenPlatformDate(event.nextAttemptAt);
              const resourceType = getOpenPlatformPublicText(event.resource?.type, 128);
              const resourceId = getOpenPlatformPublicText(event.resource?.id, 256);
              return (
                <tr
                  key={event.eventId || `domain-event-${index}`}
                  className={openPlatformClassName(namespace, OUTBOX_BLOCK, "row")}
                  data-domain-event-status={status}
                >
                  <td className={openPlatformClassName(namespace, OUTBOX_BLOCK, "cell")}>
                    <span className={openPlatformClassName(namespace, OUTBOX_BLOCK, "event-id")}>
                      {getOpenPlatformPublicText(event.eventId, 256) ?? "unknown"}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, OUTBOX_BLOCK, "cell")}>
                    {getOpenPlatformPublicText(event.type ?? event.eventType, 256) ?? "—"}
                  </td>
                  <td className={openPlatformClassName(namespace, OUTBOX_BLOCK, "cell")}>
                    {resourceType === undefined && resourceId === undefined
                      ? "—"
                      : `${resourceType ?? "—"} · ${resourceId ?? "—"}`}
                  </td>
                  <td className={openPlatformClassName(namespace, OUTBOX_BLOCK, "cell")}>
                    <span className={openPlatformClassName(namespace, OUTBOX_BLOCK, "status")} data-domain-event-status={status}>
                      {status}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, OUTBOX_BLOCK, "cell")} data-attempt={attempt}>
                    {attempt}
                  </td>
                  <td className={openPlatformClassName(namespace, OUTBOX_BLOCK, "cell")}>
                    {occurredAt.dateTime === "" ? "—" : <time dateTime={occurredAt.dateTime}>{occurredAt.label}</time>}
                  </td>
                  <td className={openPlatformClassName(namespace, OUTBOX_BLOCK, "cell")}>
                    {nextAttemptAt.dateTime === "" ? "—" : <time dateTime={nextAttemptAt.dateTime}>{nextAttemptAt.label}</time>}
                  </td>
                  <td className={openPlatformClassName(namespace, OUTBOX_BLOCK, "cell")}>
                    <span data-error-code={getOpenPlatformStatusText(event.errorCode, "none")}>
                      {getOpenPlatformPublicText(event.errorCode, 128) ?? "—"}
                    </span>
                  </td>
                  {hasActions && <td className={openPlatformClassName(namespace, OUTBOX_BLOCK, "cell")}>{renderActions?.(event)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {hasPagination && (
        <OpenPlatformPagination
          block={OUTBOX_BLOCK}
          pagination={pagination}
          cursor={cursor}
          nextCursor={nextCursor}
          previousCursor={previousCursor}
          hasMore={hasMore}
          nextSequence={nextSequence}
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

export const DomainEventList = OutboxStatusList;
export const OpenPlatformOutboxStatusList = OutboxStatusList;
export const OpenPlatformDomainEventList = OutboxStatusList;

export function DomainEventMonitor({
  onRetryEvents,
  retrying = false,
  retrySummary,
  retryError,
  retryLabel,
  retryTitle,
  showRetrySummary = true,
  title,
  actions,
  children,
  ...listProps
}: DomainEventMonitorProps) {
  const namespace = resolveOpenPlatformClassNamespace(listProps);
  const monitorTitle = getOpenPlatformPublicText(title, 256) ?? "Domain event monitor";
  const retryActionLabel = getOpenPlatformPublicText(retryLabel, 128) ?? "Retry delivery";
  const results = showRetrySummary ? getOpenPlatformSafeRetryResults(retrySummary) : [];
  const flushed = getOpenPlatformComplianceCount(retrySummary?.flushed);
  const replayed = retrySummary?.replayed === true;

  return (
    <div
      className={openPlatformClassName(namespace, "open-platform-domain-event-monitor")}
      data-open-platform-monitor="domain-events"
    >
      <div className={openPlatformClassName(namespace, "open-platform-domain-event-monitor", "toolbar")} role="group" aria-label={monitorTitle}>
        {actions !== undefined && actions !== null && (
          <div className={openPlatformClassName(namespace, "open-platform-domain-event-monitor", "actions")}>{actions}</div>
        )}
        {onRetryEvents !== undefined && (
          <button
            className={openPlatformClassName(namespace, "open-platform-domain-event-monitor", "retry")}
            type="button"
            disabled={retrying}
            aria-busy={retrying || undefined}
            onClick={() => onRetryEvents()}
          >
            {retryActionLabel}
          </button>
        )}
      </div>
      {retryError != null && (
        <ErrorState
          error={retryError}
          title={retryTitle ?? "Unable to retry delivery"}
          retryLabel={retryLabel}
          onRetry={onRetryEvents}
          classNamespace={namespace}
        />
      )}
      {showRetrySummary && retrySummary != null && (flushed !== undefined || results.length > 0) && (
        <section
          className={openPlatformClassName(namespace, "open-platform-domain-event-monitor", "retry-summary")}
          aria-label="Retry summary"
          data-open-platform-retry-summary=""
        >
          <dl className={openPlatformClassName(namespace, "open-platform-domain-event-monitor", "retry-metrics")}>
            <dt>Flushed</dt>
            <dd data-retry-metric="flushed">{flushed ?? 0}</dd>
            <dt>Replayed</dt>
            <dd data-retry-metric="replayed">{replayed ? "Yes" : "No"}</dd>
          </dl>
          {results.length === 0 ? null : (
            <ul className={openPlatformClassName(namespace, "open-platform-domain-event-monitor", "retry-results")}>
              {results.map((result) => (
                <li
                  key={result.eventId}
                  className={openPlatformClassName(namespace, "open-platform-domain-event-monitor", "retry-result")}
                  data-retry-event-id={result.eventId}
                >
                  <span className={openPlatformClassName(namespace, "open-platform-domain-event-monitor", "retry-event-id")}>
                    {result.eventId}
                  </span>
                  <span data-retry-delivered={result.delivered}>delivered {result.delivered}</span>
                  <span data-retry-dead-lettered={result.deadLettered ? "true" : "false"}>
                    dead-lettered {result.deadLettered ? "yes" : "no"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
      {children ?? (
        <OutboxStatusList
          {...listProps}
          classNamespace={namespace}
          showHeader={false}
        />
      )}
    </div>
  );
}

export const OpenPlatformDomainEventMonitor = DomainEventMonitor;

function getOpenPlatformSafeRetryResults(
  summary: OpenPlatformDomainEventRetrySummary | null | undefined,
): readonly { readonly eventId: string; readonly delivered: number; readonly deadLettered: boolean }[] {
  if (summary === undefined || summary === null || !Array.isArray(summary.results)) return [];
  const output: { eventId: string; delivered: number; deadLettered: boolean }[] = [];
  for (const item of summary.results) {
    if (output.length >= MAX_RETRY_RESULTS) break;
    if (item === null || typeof item !== "object") continue;
    output.push({
      eventId: getOpenPlatformPublicText(item.eventId, 128) ?? "unknown",
      delivered: getOpenPlatformComplianceCount(item.delivered) ?? 0,
      deadLettered: item.deadLettered === true,
    });
  }
  return output;
}

function pageItems(
  pagination: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformDomainEventSummary> | undefined,
): readonly OpenPlatformDomainEventSummary[] | undefined {
  return pagination !== undefined && "items" in pagination ? pagination.items : undefined;
}
