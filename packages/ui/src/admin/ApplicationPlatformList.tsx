import { useId, type ReactNode } from "react";
import type {
  AdminApplicationPlatform,
  AdminApplicationReadiness,
  AdminListBaseProps,
  AdminPagination,
  AdminSecretRotationTarget,
} from "./contracts.js";
import { AdminCursorPagination } from "./AdminCursorPagination.js";
import { AdminListState } from "./ListState.js";
import { AdminSecretRotationControls } from "./SecretRotationControls.js";
import {
  getAdminDate,
  getAdminDisplayValue,
  getAdminListClassSet,
  getAdminListTitle,
  getAdminLoading,
  getAdminMetadataText,
  getAdminReadinessChecks,
  getAdminReadinessStatus,
  getAdminLifecycleStatus,
  getAdminRedirectUri,
  getAdminSafeUrl,
  getAdminStatusText,
  getAdminSecretStatus,
  getAdminVersion,
} from "./listUtils.js";
import { adminClassName, resolveAdminClassNamespace } from "./theme.js";

export interface ApplicationPlatformListProps extends AdminListBaseProps {
  platforms: readonly AdminApplicationPlatform[];
  renderActions?: (platform: AdminApplicationPlatform) => ReactNode;
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
  onRotate?: (target: AdminSecretRotationTarget) => void;
  onRotateSecret?: (target: AdminSecretRotationTarget) => void;
  rotationDisabled?: boolean;
  canRotateSecret?: boolean | ((platform: AdminApplicationPlatform) => boolean);
  rotationLabel?: string;
}

function displayUriValues(
  values: readonly string[] | null | undefined,
  namespace: string,
): ReactNode {
  const normalizedValues = (Array.isArray(values) ? values : []).map((value) => getAdminRedirectUri(value)).filter((value): value is string => Boolean(value));
  if (normalizedValues.length === 0) return getAdminDisplayValue(undefined);
  return (
    <span className={adminClassName(namespace, "application-platform-list", "redirect-uris")}>
      {normalizedValues.map((value, index) => (
        <span
          className={adminClassName(namespace, "application-platform-list", "redirect-uri")}
          key={`${value}-${index}`}
        >
          {value}
        </span>
      ))}
    </span>
  );
}

function statusValue(value: string | null | undefined, fallback: string): string {
  return getAdminStatusText(value, fallback);
}

function isConfiguredSecretStatus(value: string): boolean {
  return value === "configured" || value === "active" || value === "retiring";
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
      <span className={adminClassName(namespace, block, "readiness")} data-readiness={status}>
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

function rotationTarget(platform: AdminApplicationPlatform): AdminSecretRotationTarget {
  const version = getAdminVersion(platform.version);
  const etag = getAdminMetadataText(platform.etag);
  return {
    kind: "application-platform",
    id: platform.id,
    applicationId: platform.applicationId ?? "",
    ...(version === undefined ? {} : { version, expectedVersion: version }),
    ...(etag === undefined ? {} : { etag }),
  };
}

export function ApplicationPlatformList({
  platforms,
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
  onRotate,
  onRotateSecret,
  rotationDisabled = false,
  canRotateSecret = true,
  rotationLabel,
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
}: ApplicationPlatformListProps) {
  const headingId = useId();
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const listTitle = getAdminListTitle(title, "Application platforms");
  const tableCaption = caption ?? listTitle;
  const isLoading = getAdminLoading({ loading, isLoading: isLoadingProp });
  const hasRotation = onRotate !== undefined || onRotateSecret !== undefined;
  const hasActions = renderActions !== undefined || hasRotation;
  const columnCount = hasActions ? 18 : 17;
  const rows = platforms ?? [];
  const classes = getAdminListClassSet({ ...namespaceProps, title, caption, actions }, "application-platform-list");
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
      data-admin-list="application-platforms"
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
            <th scope="col">Type</th>
            <th scope="col">External App ID</th>
            <th scope="col">Display Name</th>
            <th scope="col">Login Mode</th>
            <th scope="col">Endpoint URL</th>
            <th scope="col">Redirect URI Allowlist</th>
            <th scope="col">Status</th>
            <th scope="col">Lifecycle Status</th>
            <th scope="col">Effective Status</th>
            <th scope="col">Readiness</th>
            <th scope="col">Credential Configured</th>
            <th scope="col">Secret Status</th>
            <th scope="col">Secret Version</th>
            <th scope="col">Version</th>
            <th scope="col">ETag</th>
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
            rows.map((platform) => {
               const lifecycleStatus = getAdminLifecycleStatus(platform, platform.status);
              const effectiveStatus = statusValue(platform.effectiveStatus, "Unknown");
              const platformType = getAdminStatusText(platform.type, "Unknown platform");
              const secretStatus = getAdminSecretStatus(platform);
              const secretVersion = getAdminVersion(platform.secretVersion);
              const version = getAdminVersion(platform.version);
              const etag = getAdminMetadataText(platform.etag);
              const createdAt = platform.createdAt ? getAdminDate(platform.createdAt) : undefined;
              const updatedAt = platform.updatedAt ? getAdminDate(platform.updatedAt) : undefined;
              const endpointUrl = getAdminSafeUrl(platform.endpointUrl ?? undefined);
               const lifecycleCanRotate = lifecycleStatus !== "archived" && lifecycleStatus !== "purged" && platform.status !== "archived" && platform.status !== "purged";
               const canRotate = lifecycleCanRotate && (typeof canRotateSecret === "function" ? canRotateSecret(platform) : canRotateSecret);
              return (
                <tr key={platform.id} className={adminClassName(namespace, "application-platform-list", "row")}>
                  <td className={classes.cell}>
                    <span className={adminClassName(namespace, "application-platform-list", "type")}>
                      {platformType}
                    </span>
                  </td>
                  <td className={classes.cell}>{getAdminDisplayValue(platform.externalAppId)}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(platform.displayName)}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(platform.loginMode)}</td>
                   <td className={classes.cell}>{getAdminDisplayValue(endpointUrl)}</td>
                   <td className={classes.cell}>{displayUriValues(platform.redirectUris, namespace)}</td>
                   <td className={classes.cell}>
                    <span className={adminClassName(namespace, "application-platform-list", "status")}>
                      {statusValue(platform.status, "Unknown")}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-platform-list", "lifecycle-status")}
                      data-lifecycle-status={lifecycleStatus}
                    >
                      {lifecycleStatus}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-platform-list", "effective-status")}
                      data-effective-status={effectiveStatus}
                    >
                      {effectiveStatus}
                    </span>
                  </td>
                  <td className={classes.cell}>{readinessCell(platform.readiness, namespace, "application-platform-list")}</td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-platform-list", "credential-configured")}
                       data-credential-configured={isConfiguredSecretStatus(secretStatus) || (platform.credentialConfigured === true && secretStatus !== "revoked" && secretStatus !== "expired") ? "true" : "false"}
                     >
                       {isConfiguredSecretStatus(secretStatus) || (platform.credentialConfigured === true && secretStatus !== "revoked" && secretStatus !== "expired") ? "Configured" : "Not configured"}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-platform-list", "secret-status")}
                      data-secret-status={secretStatus}
                    >
                      {secretStatus}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-platform-list", "secret-version")}
                      data-secret-version={secretVersion}
                    >
                      {getAdminDisplayValue(secretVersion)}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span className={adminClassName(namespace, "application-platform-list", "version")} data-version={version}>
                      {getAdminDisplayValue(version)}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-platform-list", "etag")}
                      data-etag={etag}
                    >
                      {getAdminDisplayValue(etag)}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    {createdAt ? <time dateTime={createdAt.dateTime}>{createdAt.label}</time> : getAdminDisplayValue(undefined)}
                  </td>
                  <td className={classes.cell}>
                    {updatedAt ? <time dateTime={updatedAt.dateTime}>{updatedAt.label}</time> : getAdminDisplayValue(undefined)}
                  </td>
                  {hasActions && (
                    <td className={classes.cell}>
                      <div className={adminClassName(namespace, "application-platform-list", "row-actions")}>
                        {renderActions?.(platform)}
                        {hasRotation && (
                          <AdminSecretRotationControls
                            target={rotationTarget(platform)}
                            block="application-platform-list"
                            label={rotationLabel}
                            disabled={rotationDisabled}
                            canRotate={canRotate}
                            onRotate={onRotate}
                            onRotateSecret={onRotateSecret}
                            classNamespace={namespaceProps.classNamespace}
                            classNamePrefix={namespaceProps.classNamePrefix}
                            theme={namespaceProps.theme}
                          />
                        )}
                      </div>
                    </td>
                  )}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {hasPagination && (
        <AdminCursorPagination
          block="application-platform-list"
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
