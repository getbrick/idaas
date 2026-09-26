import { useId, type ReactNode } from "react";
import { OpenPlatformListState } from "./OpenPlatformListState.js";
import { OpenPlatformPagination } from "./OpenPlatformPagination.js";
import type {
  OpenPlatformListBaseProps,
  OpenPlatformPage,
  OpenPlatformPaginationState,
  OpenPlatformWebhookEndpoint,
} from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  sanitizeOpenPlatformHref,
} from "./theme.js";
import {
  getOpenPlatformDate,
  getOpenPlatformPublicText,
  getOpenPlatformSafeText,
  getOpenPlatformStatusText,
  maskOpenPlatformSecretReference,
} from "./utils.js";

export interface WebhookEndpointListProps extends OpenPlatformListBaseProps {
  webhooks?: readonly OpenPlatformWebhookEndpoint[];
  endpoints?: readonly OpenPlatformWebhookEndpoint[];
  items?: readonly OpenPlatformWebhookEndpoint[];
  data?: readonly OpenPlatformWebhookEndpoint[];
  records?: readonly OpenPlatformWebhookEndpoint[];
  pagination?: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformWebhookEndpoint>;
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
  renderActions?: (webhook: OpenPlatformWebhookEndpoint) => ReactNode;
  paginationLabel?: string;
  previousLabel?: string;
  nextLabel?: string;
}

export function WebhookEndpointList({
  webhooks,
  endpoints,
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
}: WebhookEndpointListProps) {
  const headingId = useId();
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const isLoading = isLoadingProp ?? loading ?? false;
  const rows = webhooks ?? endpoints ?? items ?? data ?? records ?? pageItems(pagination) ?? [];
  const listTitle = getOpenPlatformPublicText(title, 256) ?? "Webhook endpoints";
  const tableCaption = typeof caption === "string" ? getOpenPlatformPublicText(caption, 512) ?? listTitle : caption ?? listTitle;
  const hasActions = renderActions !== undefined;
  const columnCount = hasActions ? 7 : 6;
  const hasPagination = pagination !== undefined || cursor !== undefined || nextCursor !== undefined || previousCursor !== undefined || hasMore !== undefined || page !== undefined || pageSize !== undefined || total !== undefined || hasNextPage !== undefined || hasPreviousPage !== undefined || onCursorChange !== undefined || onNext !== undefined || onPrevious !== undefined || onLoadMore !== undefined || onPageChange !== undefined || hasNext !== undefined || hasPrevious !== undefined || onNextPage !== undefined || onPreviousPage !== undefined;

  return (
    <section
      className={openPlatformClassNames(openPlatformClassName(namespace, "webhook-endpoint-list"), className)}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-open-platform-list="webhooks"
      data-open-platform-resource="webhooks"
    >
      <header className={openPlatformClassName(namespace, "webhook-endpoint-list", "header")}>
        <h2 id={headingId} className={openPlatformClassName(namespace, "webhook-endpoint-list", "heading")}>
          {listTitle}
        </h2>
        {actions !== undefined && actions !== null && (
          <div className={openPlatformClassName(namespace, "webhook-endpoint-list", "actions")}>{actions}</div>
        )}
      </header>
      <table className={openPlatformClassName(namespace, "webhook-endpoint-list", "table")} aria-busy={isLoading || undefined}>
        <caption className={openPlatformClassName(namespace, "webhook-endpoint-list", "caption")}>{tableCaption}</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Endpoint</th>
            <th scope="col">Status</th>
            <th scope="col">Events</th>
            <th scope="col">Secret</th>
            <th scope="col">Last delivery</th>
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
            rows.map((webhook, index) => {
              const endpoint = getOpenPlatformSafeText(webhook.endpointUrl ?? webhook.endpoint_url ?? webhook.endpointURL ?? webhook.endpoint ?? webhook.url, 2048);
              const safeHref = endpoint ? sanitizeOpenPlatformHref(endpoint) : undefined;
              const eventValues = Array.isArray(webhook.events)
                ? webhook.events.map((event) => getOpenPlatformSafeText(event, 128)).filter((event): event is string => Boolean(event))
                : [];
              const secret = webhook.signingSecretReference ?? webhook.signing_secret_reference ?? webhook.signingSecretRef ?? webhook.secretReference ?? webhook.secretRef;
              const delivery = webhook.lastDeliveryAt ? getOpenPlatformDate(webhook.lastDeliveryAt) : undefined;
              return (
                <tr key={webhook.id || `webhook-${index}`} className={openPlatformClassName(namespace, "webhook-endpoint-list", "row")}>
                  <td className={openPlatformClassName(namespace, "webhook-endpoint-list", "cell")}>
                    <span className={openPlatformClassName(namespace, "webhook-endpoint-list", "name")}>
                      {getOpenPlatformSafeText(webhook.name, 256) ?? "Unnamed webhook"}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, "webhook-endpoint-list", "cell")}>
                    {safeHref ? (
                      <a className={openPlatformClassName(namespace, "webhook-endpoint-list", "endpoint")} href={safeHref}>
                        {safeHref}
                      </a>
                    ) : (
                      <span>{endpoint ? "Endpoint unavailable" : "—"}</span>
                    )}
                  </td>
                  <td className={openPlatformClassName(namespace, "webhook-endpoint-list", "cell")}>
                    <span
                      className={openPlatformClassName(namespace, "webhook-endpoint-list", "status")}
                      data-webhook-status={getOpenPlatformStatusText(webhook.status)}
                    >
                      {getOpenPlatformStatusText(webhook.status)}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, "webhook-endpoint-list", "cell")}>
                    {eventValues.length > 0 ? eventValues.join(", ") : "—"}
                  </td>
                  <td className={openPlatformClassName(namespace, "webhook-endpoint-list", "cell")}>
                    <span data-secret-reference="masked">{maskOpenPlatformSecretReference(secret)}</span>
                  </td>
                  <td className={openPlatformClassName(namespace, "webhook-endpoint-list", "cell")}>
                    {delivery ? <time dateTime={delivery.dateTime}>{delivery.label}</time> : "—"}
                  </td>
                  {hasActions && <td className={openPlatformClassName(namespace, "webhook-endpoint-list", "cell")}>{renderActions?.(webhook)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {hasPagination && (
        <OpenPlatformPagination
          block="webhook-endpoint-list"
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

export const WebhookList = WebhookEndpointList;
export const WebhooksTable = WebhookEndpointList;
export const OpenPlatformWebhookEndpointList = WebhookEndpointList;

function pageItems(
  pagination: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformWebhookEndpoint> | undefined,
): readonly OpenPlatformWebhookEndpoint[] | undefined {
  return pagination !== undefined && "items" in pagination ? pagination.items : undefined;
}
