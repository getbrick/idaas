import { useId, type ReactNode } from "react";
import type { AdminAuditEvent, AdminListBaseProps } from "./contracts.js";
import { AdminListState } from "./ListState.js";
import { getAdminAuditDetail, getAdminDate, getAdminListClassSet, getAdminListTitle, getAdminLoading, getAdminMetadataText } from "./listUtils.js";
import { adminClassName, resolveAdminClassNamespace } from "./theme.js";

export interface AuditEventListProps extends AdminListBaseProps {
  events: readonly AdminAuditEvent[];
  renderActions?: (event: AdminAuditEvent) => ReactNode;
  renderDetail?: (event: AdminAuditEvent) => ReactNode;
}

function displayValue(value: string | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  return value;
}

function getActorLabel(event: AdminAuditEvent): string {
  if (typeof event.actor === "string") return getAdminMetadataText(event.actor) || "Unknown actor";
  return getAdminMetadataText(event.actor?.name) ||
    getAdminMetadataText(event.actor?.email) ||
    getAdminMetadataText(event.actor?.id) ||
    getAdminMetadataText(event.userId) ||
    "Unknown actor";
}

function getActorId(event: AdminAuditEvent): string | undefined {
  if (typeof event.actor === "string") return getAdminMetadataText(event.userId);
  return getAdminMetadataText(event.actor?.id) ?? getAdminMetadataText(event.userId);
}

function getDetail(event: AdminAuditEvent): string {
  if (event.detail === undefined || event.detail === null) return "—";
  try {
    return JSON.stringify(getAdminAuditDetail(event.detail), null, 2) ?? "—";
  } catch {
    return "Details unavailable";
  }
}

export function AuditEventList({
  events,
  renderActions,
  renderDetail,
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
}: AuditEventListProps) {
  const headingId = useId();
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const listTitle = getAdminListTitle(title, "Audit events");
  const tableCaption = caption ?? listTitle;
  const isLoading = getAdminLoading({ loading, isLoading: isLoadingProp });
  const hasActions = renderActions !== undefined;
  const columnCount = hasActions ? 5 : 4;
  const rows = events ?? [];
  const classes = getAdminListClassSet({ ...namespaceProps, title, caption, actions }, "audit-event-list");

  return (
    <section
      className={classes.root}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-admin-list="audit-events"
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
            <th scope="col">Event</th>
            <th scope="col">Actor</th>
            <th scope="col">Occurred</th>
            <th scope="col">Details</th>
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
            rows.map((event) => {
               const occurredAt = event.occurredAt === undefined ? { dateTime: "", label: "—" } : getAdminDate(event.occurredAt);
              const actorId = getActorId(event);
              return (
                <tr key={event.id} className={adminClassName(namespace, "audit-event-list", "row")}>
                  <td className={classes.cell}>{getAdminMetadataText(event.event) ?? "Unknown event"}</td>
                  <td className={classes.cell}>
                    <span className={adminClassName(namespace, "audit-event-list", "actor")}>
                      {getActorLabel(event)}
                    </span>
                    {actorId && <span className={adminClassName(namespace, "audit-event-list", "actor-id")}>{actorId}</span>}
                  </td>
                  <td className={classes.cell}>
                    <time dateTime={occurredAt.dateTime}>{occurredAt.label}</time>
                  </td>
                  <td className={classes.cell}>
                    {renderDetail ? (
                      renderDetail(event)
                    ) : event.detail ? (
                      <pre className={adminClassName(namespace, "audit-event-list", "detail")}>{getDetail(event)}</pre>
                    ) : (
                      displayValue(undefined)
                    )}
                  </td>
                  {hasActions && <td className={classes.cell}>{renderActions?.(event)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </section>
  );
}
