import { useId, type ReactNode } from "react";
import type { AdminListBaseProps, AdminRole } from "./contracts.js";
import { AdminListState } from "./ListState.js";
import { getAdminDisplayValue, getAdminListClassSet, getAdminListTitle, getAdminLoading, getAdminMetadataText } from "./listUtils.js";
import { adminClassName, resolveAdminClassNamespace } from "./theme.js";

export interface RoleListProps extends AdminListBaseProps {
  roles: readonly AdminRole[];
  renderActions?: (role: AdminRole) => ReactNode;
}

function displayValue(value: unknown): string {
  return getAdminDisplayValue(value);
}

export function RoleList({
  roles,
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
}: RoleListProps) {
  const headingId = useId();
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const listTitle = getAdminListTitle(title, "Roles");
  const tableCaption = caption ?? listTitle;
  const isLoading = getAdminLoading({ loading, isLoading: isLoadingProp });
  const hasActions = renderActions !== undefined;
  const columnCount = hasActions ? 5 : 4;
  const rows = roles ?? [];
  const classes = getAdminListClassSet({ ...namespaceProps, title, caption, actions }, "role-list");

  return (
    <section
      className={classes.root}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-admin-list="roles"
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
            <th scope="col">Role</th>
            <th scope="col">Description</th>
            <th scope="col">Permissions</th>
            <th scope="col">Members</th>
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
           rows.map((role) => {
              const permissions = (Array.isArray(role.permissions) ? role.permissions : []).map((permission) => getAdminMetadataText(permission)).filter((permission): permission is string => Boolean(permission));
              return (
                <tr key={role.id} className={adminClassName(namespace, "role-list", "row")}>
                  <td className={classes.cell}>
                     <span className={adminClassName(namespace, "role-list", "name")}>{getAdminMetadataText(role.name) ?? "—"}</span>
                     {getAdminMetadataText(role.code) && <span className={adminClassName(namespace, "role-list", "code")}>{getAdminMetadataText(role.code)}</span>}
                  </td>
                  <td className={classes.cell}>{displayValue(role.description)}</td>
                  <td className={classes.cell}>
                    {permissions.length > 0 ? (
                      <span className={adminClassName(namespace, "role-list", "permissions")}>
                        {permissions.map((permission, index) => (
                          <span
                            className={adminClassName(namespace, "role-list", "permission")}
                            key={`${permission}-${index}`}
                          >
                            {permission}
                          </span>
                        ))}
                      </span>
                    ) : (
                      displayValue(undefined)
                    )}
                  </td>
                  <td className={classes.cell}>{displayValue(role.memberCount)}</td>
                  {hasActions && <td className={classes.cell}>{renderActions?.(role)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </section>
  );
}
