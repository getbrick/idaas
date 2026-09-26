import { useId, type ReactNode } from "react";
import type {
  AdminApplicationClient,
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

export interface ApplicationClientListProps extends AdminListBaseProps {
  clients: readonly AdminApplicationClient[];
  renderActions?: (client: AdminApplicationClient) => ReactNode;
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
  canRotateSecret?: boolean | ((client: AdminApplicationClient) => boolean);
  rotationLabel?: string;
}

function displayValues(
  values: readonly string[] | null | undefined,
  namespace: string,
  listClass: string,
): ReactNode {
  const normalizedValues = (Array.isArray(values) ? values : []).map((value) => getAdminMetadataText(value)).filter((value): value is string => Boolean(value));
  if (normalizedValues.length === 0) return getAdminDisplayValue(undefined);

  return (
    <span className={adminClassName(namespace, "application-client-list", listClass)}>
      {normalizedValues.map((value, index) => (
        <span
          className={adminClassName(namespace, "application-client-list", `${listClass}-item`)}
          key={`${value}-${index}`}
        >
          {value}
        </span>
      ))}
    </span>
  );
}

function displayUriValues(
  values: readonly string[] | null | undefined,
  namespace: string,
  listClass: string,
): ReactNode {
  const normalizedValues = (Array.isArray(values) ? values : []).map((value) => getAdminRedirectUri(value)).filter((value): value is string => Boolean(value));
  if (normalizedValues.length === 0) return getAdminDisplayValue(undefined);
  return (
    <span className={adminClassName(namespace, "application-client-list", listClass)}>
      {normalizedValues.map((value, index) => (
        <span
          className={adminClassName(namespace, "application-client-list", `${listClass}-item`)}
          key={`${value}-${index}`}
        >
          {value}
        </span>
      ))}
    </span>
  );
}

function keyTypeValue(method: string, algorithm: string | null | undefined): string {
  if (method === "private_key_jwt") {
    if (algorithm === "ES256") return "EC";
    if (algorithm === "EdDSA") return "OKP";
    return "RSA";
  }
  if (method === "none") return "none";
  return "shared-secret";
}

function statusValue(value: string | null | undefined, fallback: string): string {
  return getAdminStatusText(value, fallback);
}

function authMethodValue(value: string | null | undefined): string {
  const normalized = typeof value === "string" ? value.trim() : undefined;
  if (
    normalized === "none" ||
    normalized === "client_secret_basic" ||
    normalized === "client_secret_post" ||
    normalized === "private_key_jwt"
  ) return normalized;
  return getAdminStatusText(normalized, "Unknown");
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

function rotationTarget(client: AdminApplicationClient): AdminSecretRotationTarget {
  const version = getAdminVersion(client.version);
  const etag = getAdminMetadataText(client.etag);
  return {
    kind: "application-client",
    id: client.id,
    applicationId: client.applicationId,
    ...(version === undefined ? {} : { version, expectedVersion: version }),
    ...(etag === undefined ? {} : { etag }),
  };
}

export function ApplicationClientList({
  clients,
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
}: ApplicationClientListProps) {
  const headingId = useId();
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const listTitle = getAdminListTitle(title, "Application clients");
  const tableCaption = caption ?? listTitle;
  const isLoading = getAdminLoading({ loading, isLoading: isLoadingProp });
  const hasRotation = onRotate !== undefined || onRotateSecret !== undefined;
  const hasActions = renderActions !== undefined || hasRotation;
  const columnCount = hasActions ? 25 : 24;
  const rows = clients ?? [];
  const classes = getAdminListClassSet({ ...namespaceProps, title, caption, actions }, "application-client-list");
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
      data-admin-list="application-clients"
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
            <th scope="col">Client ID</th>
            <th scope="col">Application ID</th>
            <th scope="col">Status</th>
            <th scope="col">Lifecycle Status</th>
            <th scope="col">Effective Status</th>
            <th scope="col">Readiness</th>
            <th scope="col">Grant Types</th>
            <th scope="col">Response Types</th>
            <th scope="col">Scopes</th>
            <th scope="col">Redirect URI Allowlist</th>
            <th scope="col">Post Logout Redirect URI Allowlist</th>
            <th scope="col">Token Endpoint Auth Method</th>
            <th scope="col">Signing Algorithm</th>
            <th scope="col">Key Type</th>
            <th scope="col">JWKS URI</th>
            <th scope="col">Key ID</th>
            <th scope="col">Require PKCE</th>
            <th scope="col">Has Secret</th>
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
            rows.map((client) => {
               const lifecycleStatus = getAdminLifecycleStatus(client, client.status);
              const effectiveStatus = statusValue(client.effectiveStatus, "Unknown");
              const secretStatus = getAdminSecretStatus(client);
              const secretVersion = getAdminVersion(client.secretVersion);
              const version = getAdminVersion(client.version);
              const etag = getAdminMetadataText(client.etag);
              const createdAt = client.createdAt ? getAdminDate(client.createdAt) : undefined;
              const updatedAt = client.updatedAt ? getAdminDate(client.updatedAt) : undefined;
              const requirePkceLabel = client.requirePkce ? "Required" : "Not required";
               const hasSecretLabel = secretStatus === "not_required"
                 ? "Not required"
                 : isConfiguredSecretStatus(secretStatus) || (client.hasSecret === true && secretStatus !== "revoked" && secretStatus !== "expired")
                   ? "Configured"
                   : "Not configured";
              const jwksUri = getAdminSafeUrl(client.jwksUri ?? undefined);
              const keyId = getAdminMetadataText(client.keyId);
              const signingAlgorithm = getAdminMetadataText(client.tokenEndpointAuthSigningAlg);
              const authMethod = authMethodValue(client.tokenEndpointAuthMethod);
              const keyType = keyTypeValue(authMethod, signingAlgorithm);
               const lifecycleCanRotate = lifecycleStatus !== "archived" && lifecycleStatus !== "purged" && client.status !== "archived" && client.status !== "purged";
               const canRotate = lifecycleCanRotate && authMethod !== "none" && authMethod !== "private_key_jwt" &&
                 (typeof canRotateSecret === "function" ? canRotateSecret(client) : canRotateSecret);
              return (
                <tr key={client.id} className={adminClassName(namespace, "application-client-list", "row")}>
                  <td className={classes.cell}>{getAdminDisplayValue(client.clientId)}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(client.applicationId)}</td>
                  <td className={classes.cell}>
                    <span className={adminClassName(namespace, "application-client-list", "status")}>
                      {statusValue(client.status, "Unknown")}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-client-list", "lifecycle-status")}
                      data-lifecycle-status={lifecycleStatus}
                    >
                      {lifecycleStatus}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-client-list", "effective-status")}
                      data-effective-status={effectiveStatus}
                    >
                      {effectiveStatus}
                    </span>
                  </td>
                  <td className={classes.cell}>{readinessCell(client.readiness, namespace, "application-client-list")}</td>
                  <td className={classes.cell}>{displayValues(client.grantTypes, namespace, "grant-types")}</td>
                  <td className={classes.cell}>{displayValues(client.responseTypes, namespace, "response-types")}</td>
                  <td className={classes.cell}>{displayValues(client.scopes, namespace, "scopes")}</td>
                  <td className={classes.cell}>{displayUriValues(client.redirectUris, namespace, "redirect-uris")}</td>
                  <td className={classes.cell}>{displayUriValues(client.postLogoutRedirectUris, namespace, "post-logout-redirect-uris")}</td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-client-list", "auth-method")}
                      data-auth-method={authMethod}
                    >
                      {authMethod}
                    </span>
                  </td>
                  <td className={classes.cell}>{getAdminDisplayValue(signingAlgorithm)}</td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-client-list", "key-type")}
                      data-key-type={keyType}
                    >
                      {keyType}
                    </span>
                  </td>
                  <td className={classes.cell}>{getAdminDisplayValue(jwksUri)}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(keyId)}</td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-client-list", "require-pkce")}
                      data-require-pkce={client.requirePkce ? "true" : "false"}
                    >
                      {requirePkceLabel}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-client-list", "has-secret")}
                       data-has-secret={hasSecretLabel === "Configured" ? "true" : "false"}
                    >
                      {hasSecretLabel}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-client-list", "secret-status")}
                      data-secret-status={secretStatus}
                    >
                      {secretStatus}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-client-list", "secret-version")}
                      data-secret-version={secretVersion}
                    >
                      {getAdminDisplayValue(secretVersion)}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span className={adminClassName(namespace, "application-client-list", "version")} data-version={version}>
                      {getAdminDisplayValue(version)}
                    </span>
                  </td>
                  <td className={classes.cell}>
                    <span
                      className={adminClassName(namespace, "application-client-list", "etag")}
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
                      <div className={adminClassName(namespace, "application-client-list", "row-actions")}>
                        {renderActions?.(client)}
                        {hasRotation && (
                          <AdminSecretRotationControls
                            target={rotationTarget(client)}
                            block="application-client-list"
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
          block="application-client-list"
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
