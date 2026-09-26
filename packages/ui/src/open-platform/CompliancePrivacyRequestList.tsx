import { useId, type ReactNode } from "react";
import { OpenPlatformListState } from "./OpenPlatformListState.js";
import { OpenPlatformPagination } from "./OpenPlatformPagination.js";
import type {
  OpenPlatformCompliancePrivacyRequest,
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
  getOpenPlatformSafeEvidenceSummary,
  getOpenPlatformSafeSubjectRef,
  getOpenPlatformSafeTextList,
  getOpenPlatformStatusText,
  maskOpenPlatformOperatorRef,
} from "./utils.js";

export interface CompliancePrivacyRequestListProps extends OpenPlatformListBaseProps {
  privacyRequests?: readonly OpenPlatformCompliancePrivacyRequest[];
  requests?: readonly OpenPlatformCompliancePrivacyRequest[];
  items?: readonly OpenPlatformCompliancePrivacyRequest[];
  data?: readonly OpenPlatformCompliancePrivacyRequest[];
  records?: readonly OpenPlatformCompliancePrivacyRequest[];
  pagination?: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformCompliancePrivacyRequest>;
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
  renderActions?: (request: OpenPlatformCompliancePrivacyRequest) => ReactNode;
  renderDetail?: (request: OpenPlatformCompliancePrivacyRequest) => ReactNode;
  paginationLabel?: string;
  previousLabel?: string;
  nextLabel?: string;
}

const PRIVACY_REQUEST_BLOCK = "compliance-privacy-request-list";
const PRIVACY_REQUEST_COLUMN_COUNT = 8;

export function CompliancePrivacyRequestList({
  privacyRequests,
  requests,
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
}: CompliancePrivacyRequestListProps) {
  const headingId = useId();
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const isLoading = isLoadingProp ?? loading ?? false;
  const rows = privacyRequests ?? requests ?? items ?? data ?? records ?? pageItems(pagination) ?? [];
  const listTitle = getOpenPlatformPublicText(title, 256) ?? "Privacy requests";
  const tableCaption = typeof caption === "string" ? getOpenPlatformPublicText(caption, 512) ?? listTitle : caption ?? listTitle;
  const hasActions = renderActions !== undefined;
  const hasDetail = renderDetail !== undefined;
  const columnCount = PRIVACY_REQUEST_COLUMN_COUNT + (hasActions ? 1 : 0) + (hasDetail ? 1 : 0);
  const hasPagination = pagination !== undefined || cursor !== undefined || nextCursor !== undefined || previousCursor !== undefined || hasMore !== undefined || nextSequence !== undefined || page !== undefined || pageSize !== undefined || total !== undefined || hasNextPage !== undefined || hasPreviousPage !== undefined || onCursorChange !== undefined || onNext !== undefined || onPrevious !== undefined || onLoadMore !== undefined || onPageChange !== undefined || hasNext !== undefined || hasPrevious !== undefined || onNextPage !== undefined || onPreviousPage !== undefined;

  return (
    <section
      className={openPlatformClassNames(openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK), className)}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-open-platform-list="compliance-privacy-requests"
      data-open-platform-resource="compliance-privacy-requests"
    >
      <header className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "header")}>
        <h2 id={headingId} className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "heading")}>
          {listTitle}
        </h2>
        {actions !== undefined && actions !== null && (
          <div className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "actions")}>{actions}</div>
        )}
      </header>
      <table className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "table")} aria-busy={isLoading || undefined}>
        <caption className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "caption")}>{tableCaption}</caption>
        <thead>
          <tr>
            <th scope="col">Request</th>
            <th scope="col">Type</th>
            <th scope="col">Status</th>
            <th scope="col">Subject</th>
            <th scope="col">Identity</th>
            <th scope="col">SLA</th>
            <th scope="col">Received</th>
            <th scope="col">Assets</th>
            {hasDetail && <th scope="col">Details</th>}
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
            rows.map((request, index) => {
              const status = getOpenPlatformStatusText(request.status);
              const requestType = getOpenPlatformStatusText(request.requestType, "Unknown");
              const subjectCount = getOpenPlatformComplianceCount(request.subjectCount);
              const assetIds = getOpenPlatformSafeTextList(request.dataAssetIds, 4);
              const verification = request.identityVerification;
              const verificationStatus = getOpenPlatformStatusText(verification?.status, "Unknown");
              const sla = request.sla;
              const slaState = getOpenPlatformStatusText(sla?.state, "Unknown");
              const dueAt = getOpenPlatformDate(sla?.dueAt);
              const receivedAt = getOpenPlatformDate(request.receivedAt ?? request.createdAt);
              return (
                <tr
                  key={request.id || `privacy-request-${index}`}
                  className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "row")}
                  data-privacy-request-status={status}
                >
                  <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>
                    <span className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "request-id")}>
                      {getOpenPlatformPublicText(request.id, 256) ?? "Unknown request"}
                    </span>
                    {request.statusReason === null || request.statusReason === undefined
                      ? null
                      : (
                        <span className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "status-reason")}>
                          {getOpenPlatformPublicText(request.statusReason, 256) ?? "—"}
                        </span>
                      )}
                  </td>
                  <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>{requestType}</td>
                  <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>
                    <span
                      className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "status")}
                      data-privacy-request-status={status}
                    >
                      {status}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>
                    <span data-subject-ref="masked">{getOpenPlatformSafeSubjectRef(request)}</span>
                    {subjectCount === undefined
                      ? null
                      : (
                        <span className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "subject-count")}>
                          {subjectCount} subject{subjectCount === 1 ? "" : "s"}
                        </span>
                      )}
                  </td>
                  <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>
                    <span data-identity-status={verificationStatus}>{verificationStatus}</span>
                    <span className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "identity-meta")}>
                      {getOpenPlatformPublicText(verification?.method, 64) ?? "—"} · {" "}
                      {maskOpenPlatformOperatorRef(verification?.verifiedByRef)}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>
                    <span data-sla-state={slaState}>{slaState}</span>
                    {dueAt.dateTime === "" ? null : (
                      <time className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "sla-due")} dateTime={dueAt.dateTime}>
                        {dueAt.label}
                      </time>
                    )}
                  </td>
                  <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>
                    {receivedAt.dateTime === "" ? "—" : <time dateTime={receivedAt.dateTime}>{receivedAt.label}</time>}
                  </td>
                  <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>
                    {assetIds.length === 0 ? "—" : assetIds.join(", ")}
                  </td>
                  {hasDetail && <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>{renderDetail?.(request)}</td>}
                  {hasActions && <td className={openPlatformClassName(namespace, PRIVACY_REQUEST_BLOCK, "cell")}>{renderActions?.(request)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {hasPagination && (
        <OpenPlatformPagination
          block={PRIVACY_REQUEST_BLOCK}
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

export const OpenPlatformCompliancePrivacyRequestList = CompliancePrivacyRequestList;
export const PrivacyRequestList = CompliancePrivacyRequestList;
export const CompliancePrivacyRequestsTable = CompliancePrivacyRequestList;

export function getOpenPlatformSafePrivacyRequestEvidence(
  request: OpenPlatformCompliancePrivacyRequest | null | undefined,
): readonly { readonly kind: string; readonly reference: string; readonly recordedAt?: string }[] {
  const evidence = request?.decision?.evidence ?? request?.identityVerification?.evidence;
  return getOpenPlatformSafeEvidenceSummary(evidence, 4);
}

function pageItems(
  pagination: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformCompliancePrivacyRequest> | undefined,
): readonly OpenPlatformCompliancePrivacyRequest[] | undefined {
  return pagination !== undefined && "items" in pagination ? pagination.items : undefined;
}
