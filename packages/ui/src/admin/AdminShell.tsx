import { useId, type ReactNode } from "react";
import type { AdminNavigationItem } from "./contracts.js";
import { getAdminMetadataText } from "./listUtils.js";
import {
  adminClassName,
  adminClassNames,
  resolveAdminClassNamespace,
  sanitizeAdminHref,
  type AdminClassNamespaceProps,
} from "./theme.js";

export interface AdminShellProps extends AdminClassNamespaceProps {
  title: string;
  description?: ReactNode;
  navigation?: readonly AdminNavigationItem[];
  navigationLabel?: string;
  activeItemId?: string;
  activeItem?: string;
  onNavigate?: (item: AdminNavigationItem) => void;
  headerActions?: ReactNode;
  footer?: ReactNode;
  busy?: boolean;
  loading?: boolean;
  children: ReactNode;
}

export function AdminShell({
  title,
  description,
  navigation,
  navigationLabel,
  activeItemId,
  activeItem,
  onNavigate,
  headerActions,
  footer,
  busy,
  loading,
  children,
  className,
  ...namespaceProps
}: AdminShellProps) {
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const headingId = useId();
  const shellTitle = title.trim() || "Admin console";
  const navLabel = navigationLabel?.trim() || "Admin navigation";
  const selectedItemId = activeItemId ?? activeItem;
  const isBusy = busy ?? loading ?? false;

  function handleNavigate(item: AdminNavigationItem) {
    if (item.disabled) return;
    item.onSelect?.(item);
    onNavigate?.(item);
  }

  return (
    <div
      className={adminClassNames(adminClassName(namespace, "shell"), className)}
      data-admin-shell=""
      aria-busy={isBusy || undefined}
    >
      <header className={adminClassName(namespace, "shell", "header")}>
        <div className={adminClassName(namespace, "shell", "heading")}>
          <h1 id={headingId} className={adminClassName(namespace, "shell", "title")}>
            {shellTitle}
          </h1>
          {description !== undefined && description !== null && (
            <div className={adminClassName(namespace, "shell", "description")}>{description}</div>
          )}
        </div>
        {headerActions !== undefined && headerActions !== null && (
          <div className={adminClassName(namespace, "shell", "header-actions")} role="group" aria-label="Header actions">
            {headerActions}
          </div>
        )}
      </header>
      {navigation && navigation.length > 0 && (
        <nav className={adminClassName(namespace, "shell", "navigation")} aria-label={navLabel}>
          <ul className={adminClassName(namespace, "shell", "navigation-list")}>
            {navigation.map((item, index) => {
               const itemLabel = getAdminMetadataText(item.label) || getAdminMetadataText(item.id) || "Navigation item";
              const itemClassName = adminClassName(namespace, "shell", "navigation-item");
              const isCurrent = selectedItemId === item.id;
              const href = item.href ? sanitizeAdminHref(item.href) : undefined;
              if (href) {
                return (
                  <li className={itemClassName} key={`${item.id}-${index}`}>
                    <a
                      className={adminClassName(namespace, "shell", "navigation-link")}
                      href={href}
                      aria-current={isCurrent ? "page" : undefined}
                      aria-disabled={item.disabled ? true : undefined}
                      onClick={
                        item.disabled
                          ? (event) => event.preventDefault()
                          : () => handleNavigate(item)
                      }
                    >
                      {itemLabel}
                    </a>
                  </li>
                );
              }
              return (
                <li className={itemClassName} key={`${item.id}-${index}`}>
                  <button
                    className={adminClassName(namespace, "shell", "navigation-button")}
                    type="button"
                    disabled={item.disabled}
                    aria-current={isCurrent ? "page" : undefined}
                    onClick={() => handleNavigate(item)}
                  >
                    {itemLabel}
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>
      )}
      <main className={adminClassName(namespace, "shell", "main")} aria-labelledby={headingId}>
        {children}
      </main>
      {footer !== undefined && footer !== null && (
        <footer className={adminClassName(namespace, "shell", "footer")}>{footer}</footer>
      )}
    </div>
  );
}
