import { useId, type ReactNode } from "react";
import type { AdminApplication, AdminApplicationReadiness, AdminListBaseProps, AdminPagination } from "./contracts.js";
import { AdminCursorPagination } from "./AdminCursorPagination.js";
import { AdminListState } from "./ListState.js";
import {
  getAdminDate,
  getAdminDisplayValue,
  getAdminListClassSet,
  getAdminListTitle,
  getAdminLoading,
  getAdminMetadataText,
  getAdminReadinessChecks,
  getAdminReadinessStatus,
  getAdminStatusText,
  getAdminVersion,
} from "./listUtils.js";
import { adminClassName, resolveAdminClassNamespace } from "./theme.js";

export interface ApplicationListProps extends AdminListBaseProps {
  applications: readonly AdminApplication[];
  renderActions?: (application: AdminApplication) => ReactNode;
  pagination?: AdminPagination;
  cursor?: string;
  nextCursor?: string;
  previousCursor?: string;
  hasMore?: boolean;
  page?: number;
  pageSize?: number;
  total?: number;
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

function statusValue(value: string | null | undefined, fallback: string): string {
  return getAdminStatusText(value, fallback);
}

function readinessCell(
  readiness: AdminApplicationReadiness | null | undefined,
  namespace: string,
  block: string,
): ReactNode {
  const status = getAdminReadinessStatus(readiness);
  const checks = getAdminReadinessChecks(readiness);
  return (
    <>
      <span
        className={adminClassName(namespace, block, "readiness")}
        data-readiness={status}
      >
        {status}
      </span>
      {checks.length > 0 && (
        <span className={adminClassName(namespace, block, "readiness-checks")}>
          {checks.map((check, index) => {
            const label = getAdminMetadataText(check.name) ?? getAdminMetadataText(check.id) ?? `Check ${index + 1}`;
            const checkStatus = getAdminMetadataText(check.status) ?? (check.ready === true ? "ready" : check.ready === false ? "not_ready" : "unknown");
            return (
              <span
                className={adminClassName(namespace, block, "readiness-check")}
                data-readiness-check={checkStatus}
                key={`${label}-${index}`}
              >
                {label}: {checkStatus}
              </span>
            );
          })}
        </span>
      )}
    </>
  );
}

export function ApplicationList({
  applications,
  renderActions,
  pagination,
  cursor,
  nextCursor,
  previousCursor,
  hasMore,
  page: pageProp,
  pageSize: pageSizeProp,
  total: totalProp,
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
  ...namespaceProps
}: ApplicationListProps) {
  const headingId = useId();
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const listTitle = getAdminListTitle(title, "Applications");
  const tableCaption = caption ?? listTitle;
  const isLoading = getAdminLoading({ loading, isLoading: isLoadingProp });
  const hasActions = renderActions !== undefined;
  const columnCount = hasActions ? 13 : 12;
  const rows = applications ?? [];
  const classes = getAdminListClassSet({ ...namespaceProps, title, caption, actions }, "application-list");
  const hasPagination =
    pagination !== undefined ||
    cursor !== undefined ||
    nextCursor !== undefined ||
    previousCursor !== undefined ||
    hasMore !== undefined ||
    pageProp !== undefined ||
    pageSizeProp !== undefined ||
    totalProp !== undefined ||
    hasNextPageProp !== undefined ||
    hasPreviousPageProp !== undefined ||
    onCursorChangeProp !== undefined ||
    onNextProp !== undefined ||
    onPreviousProp !== undefined ||
    onLoadMoreProp !== undefined ||
    hasNextProp !== undefined ||
    hasPreviousProp !== undefined ||
    onPageChangeProp !== undefined;

  return (
    <section
      className={classes.root}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-admin-list="applications"
    >
      <header className={classes.header}>
        <h2 id={headingId} className={classes.heading}>
          {listTitle}
        </h2>
        {actions !== undefined && actions !== null && <div className={classes.actions}>{actions}</div>}
      </header>
      <table className={classes.table} aria-busy={isLoading || undefined}>
        <caption className={classes.caption}>{tableCaption}</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Slug</th>
            <th scope="col">Application Type</th>
            <th scope="col">Status</th>
            <th scope="col">Lifecycle Status</th>
            <th scope="col">Effective Status</th>
            <th scope="col">Readiness</th>
            <th scope="col">Version</th>
            <th scope="col">ETag</th>
            <th scope="col">Description</th>
            <th scope="col">Created</th>
            <th scope="col">Updated</th>
            {hasActions && <th scope="col">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {error != null || isLoading || rows.length === 0 ? (
            <AdminListState
              classNamespace={namespaceProps.classNamespace}
              classNamePrefix={namespaceProps.classNamePrefix}
              theme={namespaceProps.theme}
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
            rows.map((application) => {
              const lifecycleStatus = statusValue(application.lifecycleStatus ?? application.status, "Unknown");
              const effectiveStatus = statusValue(application.effectiveStatus, "Unknown");
              const applicationType = getAdminStatusText(application.applicationType, "—");
              const version = getAdminVersion(application.version);
              const etag = getAdminMetadataText(application.etag);
              const createdAt = application.createdAt ? getAdminDate(application.createdAt) : undefined;
              const updatedAt = application.updatedAt ? getAdminDate(application.updatedAt) : undefined;
              return (
                <tr key={application.id} className={adminClassName(namespace, "application-list", "row")}>
                  <td className={classes.cell}>{getAdminDisplayValue(application.name)}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(application.slug)}</td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-list", "application-type")}
                      data-application-type={applicationType}
                    >
                      {applicationType}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span className={adminClassName(namespace, "application-list", "status")}>
                      {statusValue(application.status, "Unknown")}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-list", "lifecycle-status")}
                      data-lifecycle-status={lifecycleStatus}
                    >
                      {lifecycleStatus}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-list", "effective-status")}
                      data-effective-status={effectiveStatus}
                    >
                      {effectiveStatus}
                    </span>
                  </td>
                  <td className={classes.cell}>{readinessCell(application.readiness, namespace, "application-list")}</td>
                  <td className={classes.cell}>
                    <span className={adminClassName(namespace, "application-list", "version")} data-version={version}>
                      {getAdminDisplayValue(version)}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-list", "etag")}
                      data-etag={etag}
                    >
                      {getAdminDisplayValue(etag)}
                    </span>
                  </td>
                  <td className={classes.cell}>{getAdminDisplayValue(application.description)}</td>
                  <td className={classes.cell}>
                    {createdAt ? <time dateTime={createdAt.dateTime}>{createdAt.label}</time> : getAdminDisplayValue(undefined)}
                  </td>
                  <td className={classes.cell}>
                    {updatedAt ? <time dateTime={updatedAt.dateTime}>{updatedAt.label}</time> : getAdminDisplayValue(undefined)}
                  </td>
                  {hasActions && <td className={classes.cell}>{renderActions?.(application)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {hasPagination && (
        <AdminCursorPagination
          block="application-list"
          pagination={pagination}
          cursor={cursor}
          nextCursor={nextCursor}
          previousCursor={previousCursor}
          hasMore={hasMore}
          page={pageProp}
          pageSize={pageSizeProp}
          total={totalProp}
          itemCount={rows.length}
          hasNextPage={hasNextPageProp}
          hasPreviousPage={hasPreviousPageProp}
          onCursorChange={onCursorChangeProp}
          onNext={onNextProp}
          onPrevious={onPreviousProp}
          onLoadMore={onLoadMoreProp}
          hasNext={hasNextProp}
          hasPrevious={hasPreviousProp}
          onPageChange={onPageChangeProp}
          paginationLabel={paginationLabel}
          previousLabel={previousLabel}
          nextLabel={nextLabel}
          classNamespace={namespaceProps.classNamespace}
          classNamePrefix={namespaceProps.classNamePrefix}
          theme={namespaceProps.theme}
        />
      )}
    </section>
  );
}
