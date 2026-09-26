import { useId, type ReactNode } from "react";
import type {
  AdminApplicationExternalIdentity,
  AdminListBaseProps,
  AdminPagination,
} from "./contracts.js";
import { AdminCursorPagination } from "./AdminCursorPagination.js";
import { AdminListState } from "./ListState.js";
import {
  getAdminDate,
  getAdminDisplayValue,
  getAdminListClassSet,
  getAdminListTitle,
  getAdminLoading,
  getAdminMetadataText,
  getAdminVersion,
} from "./listUtils.js";
import { adminClassName, resolveAdminClassNamespace } from "./theme.js";

export interface ApplicationExternalIdentityListProps extends AdminListBaseProps {
  identities?: readonly AdminApplicationExternalIdentity[];
  externalIdentities?: readonly AdminApplicationExternalIdentity[];
  applicationExternalIdentities?: readonly AdminApplicationExternalIdentity[];
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

function safeIdentityValue(value: string | null | undefined): string | undefined {
  return getAdminMetadataText(value, 2048);
}

function displayScopes(
  scopes: readonly string[] | null | undefined,
  namespace: string,
): ReactNode {
  const values = (scopes ?? []).map((scope) => safeIdentityValue(scope)).filter((scope): scope is string => Boolean(scope));
  if (values.length === 0) return getAdminDisplayValue(undefined);
  return (
    <span className={adminClassName(namespace, "application-external-identity-list", "scopes")}>
      {values.map((value, index) => (
        <span
          className={adminClassName(namespace, "application-external-identity-list", "scope")}
          key={`${value}-${index}`}
        >
          {value}
        </span>
      ))}
    </span>
  );
}

export function ApplicationExternalIdentityList({
  identities,
  externalIdentities,
  applicationExternalIdentities,
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
}: ApplicationExternalIdentityListProps) {
  const headingId = useId();
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const listTitle = getAdminListTitle(title, "External identities");
  const tableCaption = caption ?? listTitle;
  const isLoading = getAdminLoading({ loading, isLoading: isLoadingProp });
  const rows = identities ?? externalIdentities ?? applicationExternalIdentities ?? [];
  const columnCount = 16;
  const classes = getAdminListClassSet({ ...namespaceProps, title, caption, actions }, "application-external-identity-list");
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
      aria-readonly="true"
      data-admin-list="application-external-identities"
      data-admin-resource="external-identities"
      data-admin-read-only="true"
      data-read-only="true"
    >
      <header className={classes.header}>
        <h2 id={headingId} className={classes.heading}>
          {listTitle}
        </h2>
        {actions !== undefined && actions !== null && <div className={classes.actions}>{actions}</div>}
      </header>
      <table
        className={classes.table}
        aria-readonly="true"
        aria-busy={isLoading || undefined}
      >
        <caption className={classes.caption}>{tableCaption}</caption>
        <thead>
          <tr>
            <th scope="col">Application ID</th>
            <th scope="col">Provider</th>
            <th scope="col">Platform</th>
            <th scope="col">App ID</th>
            <th scope="col">External App ID</th>
            <th scope="col">Subject</th>
            <th scope="col">Display Name</th>
            <th scope="col">Email</th>
            <th scope="col">OpenID</th>
            <th scope="col">UnionID</th>
            <th scope="col">Scopes</th>
            <th scope="col">Version</th>
            <th scope="col">Linked</th>
            <th scope="col">Last Authenticated</th>
            <th scope="col">Created</th>
            <th scope="col">Updated</th>
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
            rows.map((identity) => {
              const provider = safeIdentityValue(identity.provider);
              const subject = safeIdentityValue(identity.subject);
              const openid = safeIdentityValue(identity.openid);
              const unionid = safeIdentityValue(identity.unionid);
              const version = getAdminVersion(identity.version);
              const linkedAt = identity.linkedAt ? getAdminDate(identity.linkedAt) : undefined;
              const lastAuthenticatedAt = identity.lastAuthenticatedAt
                ? getAdminDate(identity.lastAuthenticatedAt)
                : undefined;
              const createdAt = identity.createdAt ? getAdminDate(identity.createdAt) : undefined;
              const updatedAt = identity.updatedAt ? getAdminDate(identity.updatedAt) : undefined;
              return (
                <tr key={identity.id} className={adminClassName(namespace, "application-external-identity-list", "row")}>
                  <td className={classes.cell}>{getAdminDisplayValue(safeIdentityValue(identity.applicationId))}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(provider)}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(safeIdentityValue(identity.platform))}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(safeIdentityValue(identity.appId))}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(safeIdentityValue(identity.externalAppId))}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(subject)}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(safeIdentityValue(identity.displayName))}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(safeIdentityValue(identity.email))}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(openid)}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(unionid)}</td>
                  <td className={classes.cell}>{displayScopes(identity.scopes, namespace)}</td>
                  <td className={classes.cell}>{getAdminDisplayValue(version)}</td>
                  <td className={classes.cell}>
                    {linkedAt ? <time dateTime={linkedAt.dateTime}>{linkedAt.label}</time> : getAdminDisplayValue(undefined)}
                  </td>
                  <td className={classes.cell}>
                    {lastAuthenticatedAt ? (
                      <time dateTime={lastAuthenticatedAt.dateTime}>{lastAuthenticatedAt.label}</time>
                    ) : getAdminDisplayValue(undefined)}
                  </td>
                  <td className={classes.cell}>
                    {createdAt ? <time dateTime={createdAt.dateTime}>{createdAt.label}</time> : getAdminDisplayValue(undefined)}
                  </td>
                  <td className={classes.cell}>
                    {updatedAt ? <time dateTime={updatedAt.dateTime}>{updatedAt.label}</time> : getAdminDisplayValue(undefined)}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {hasPagination && (
        <AdminCursorPagination
          block="application-external-identity-list"
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

export const ExternalIdentityList = ApplicationExternalIdentityList;
export const ApplicationExternalIdentitiesList = ApplicationExternalIdentityList;
export const ApplicationIdentityList = ApplicationExternalIdentityList;
export type ApplicationExternalIdentitiesListProps = ApplicationExternalIdentityListProps;
export type ApplicationIdentityListProps = ApplicationExternalIdentityListProps;
