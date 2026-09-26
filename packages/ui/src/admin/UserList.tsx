import { useId, type ReactNode } from "react";
import type { AdminListBaseProps, AdminUser } from "./contracts.js";
import { AdminListState } from "./ListState.js";
import { getAdminDate, getAdminDisplayValue, getAdminListClassSet, getAdminListTitle, getAdminLoading, getAdminMetadataText } from "./listUtils.js";
import { adminClassName, resolveAdminClassNamespace } from "./theme.js";

export interface UserListProps extends AdminListBaseProps {
  users: readonly AdminUser[];
  renderActions?: (user: AdminUser) => ReactNode;
}

function displayValue(value: unknown): string {
  return getAdminDisplayValue(value);
}

function getUserRoles(user: AdminUser): readonly string[] {
  const roles = (Array.isArray(user.roles) ? user.roles : []).map((role) => getAdminMetadataText(role)).filter((role): role is string => Boolean(role));
  if (roles.length > 0) return roles;
  const role = getAdminMetadataText(user.role);
  return role ? [role] : [];
}

export function UserList({
  users,
  renderActions,
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
}: UserListProps) {
  const headingId = useId();
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const listTitle = getAdminListTitle(title, "Users");
  const tableCaption = caption ?? listTitle;
  const isLoading = getAdminLoading({ loading, isLoading: isLoadingProp });
  const hasActions = renderActions !== undefined;
  const columnCount = hasActions ? 6 : 5;
  const rows = users ?? [];
  const classes = getAdminListClassSet({ ...namespaceProps, title, caption, actions }, "user-list");

  return (
    <section
      className={classes.root}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-admin-list="users"
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
            <th scope="col">User</th>
            <th scope="col">Email</th>
            <th scope="col">Status</th>
            <th scope="col">Roles</th>
            <th scope="col">Created</th>
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
            rows.map((user) => {
              const roles = getUserRoles(user);
               const name = getAdminMetadataText(user.name) || getAdminMetadataText(user.email) || getAdminMetadataText(user.id) || "Unnamed user";
               const status = getAdminMetadataText(user.status) ?? "Unknown";
              const createdAt = user.createdAt ? getAdminDate(user.createdAt) : undefined;
              return (
                <tr key={user.id} className={adminClassName(namespace, "user-list", "row")}>
                  <td className={classes.cell}>{name}</td>
                  <td className={classes.cell}>{displayValue(user.email)}</td>
                  <td className={classes.cell}>
                    <span className={adminClassName(namespace, "user-list", "status")}>{status}</span>
                  </td>
                  <td className={classes.cell}>
                    {roles.length > 0 ? (
                      <span className={adminClassName(namespace, "user-list", "roles")}>
                        {roles.map((role, index) => (
                          <span className={adminClassName(namespace, "user-list", "role")} key={`${role}-${index}`}>
                            {role}
                          </span>
                        ))}
                      </span>
                    ) : (
                      displayValue(undefined)
                    )}
                  </td>
                  <td className={classes.cell}>
                    {createdAt ? <time dateTime={createdAt.dateTime}>{createdAt.label}</time> : displayValue(undefined)}
                  </td>
                  {hasActions && <td className={classes.cell}>{renderActions?.(user)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </section>
  );
}
