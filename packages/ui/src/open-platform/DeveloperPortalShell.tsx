import { useId, type MouseEvent, type ReactNode } from "react";
import type { DeveloperPortalNavigationItem } from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  sanitizeOpenPlatformHref,
  type OpenPlatformClassNamespaceProps,
} from "./theme.js";
import { getOpenPlatformText } from "./utils.js";

export type DeveloperPortalNavigateEvent = MouseEvent<HTMLAnchorElement | HTMLButtonElement>;

export interface DeveloperPortalShellProps extends OpenPlatformClassNamespaceProps {
  title: string;
  productName?: ReactNode;
  description?: ReactNode;
  navigation?: readonly DeveloperPortalNavigationItem[];
  navigationLabel?: string;
  activeItemId?: string;
  onNavigate?: (item: DeveloperPortalNavigationItem, event: DeveloperPortalNavigateEvent) => void;
  headerActions?: ReactNode;
  footer?: ReactNode;
  busy?: boolean;
  skipLinkLabel?: string;
  children: ReactNode;
}

export function DeveloperPortalShell({
  title,
  productName,
  description,
  navigation,
  navigationLabel,
  activeItemId,
  onNavigate,
  headerActions,
  footer,
  busy = false,
  skipLinkLabel,
  children,
  className,
  ...namespaceProps
}: DeveloperPortalShellProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const headingId = useId();
  const mainId = useId();
  const shellTitle = getOpenPlatformText(title, 256) ?? "Developer portal";
  const navLabel = getOpenPlatformText(navigationLabel, 128) ?? "Developer portal navigation";
  const skipLabel = getOpenPlatformText(skipLinkLabel, 128) ?? "Skip to content";

  function handleNavigate(item: DeveloperPortalNavigationItem, event: DeveloperPortalNavigateEvent) {
    if (item.disabled) {
      event.preventDefault();
      return;
    }
    item.onSelect?.(item);
    onNavigate?.(item, event);
  }

  return (
    <div
      className={openPlatformClassNames(openPlatformClassName(namespace, "developer-portal-shell"), className)}
      data-developer-portal-shell=""
      aria-busy={busy || undefined}
    >
      <a className={openPlatformClassName(namespace, "developer-portal-shell", "skip-link")} href={`#${mainId}`}>
        {skipLabel}
      </a>
      <header className={openPlatformClassName(namespace, "developer-portal-shell", "header")}>
        <div className={openPlatformClassName(namespace, "developer-portal-shell", "heading")}>
          {productName !== undefined && productName !== null && (
            <div className={openPlatformClassName(namespace, "developer-portal-shell", "product-name")}>{productName}</div>
          )}
          <h1 id={headingId} className={openPlatformClassName(namespace, "developer-portal-shell", "title")}>
            {shellTitle}
          </h1>
          {description !== undefined && description !== null && (
            <div className={openPlatformClassName(namespace, "developer-portal-shell", "description")}>{description}</div>
          )}
        </div>
        {headerActions !== undefined && headerActions !== null && (
          <div
            className={openPlatformClassName(namespace, "developer-portal-shell", "header-actions")}
            role="group"
            aria-label="Developer portal account actions"
          >
            {headerActions}
          </div>
        )}
      </header>
      {navigation && navigation.length > 0 && (
        <nav className={openPlatformClassName(namespace, "developer-portal-shell", "navigation")} aria-label={navLabel}>
          <ul className={openPlatformClassName(namespace, "developer-portal-shell", "navigation-list")}>
            {navigation.map((item, index) => {
              const itemLabel = getOpenPlatformText(item.label, 128) ?? getOpenPlatformText(item.id, 128) ?? "Navigation item";
              const itemClassName = openPlatformClassName(namespace, "developer-portal-shell", "navigation-item");
              const isCurrent = activeItemId === item.id;
              const href = item.href ? sanitizeOpenPlatformHref(item.href) : undefined;
              const content = (
                <>
                  <span>{itemLabel}</span>
                  {item.badge !== undefined && item.badge !== null && (
                    <span className={openPlatformClassName(namespace, "developer-portal-shell", "navigation-badge")}>
                      {item.badge}
                    </span>
                  )}
                </>
              );
              return (
                <li className={itemClassName} key={`${item.id}-${index}`}>
                  {item.disabled ? (
                    <button
                      className={openPlatformClassName(namespace, "developer-portal-shell", "navigation-button")}
                      type="button"
                      disabled
                      aria-current={isCurrent ? "page" : undefined}
                    >
                      {content}
                    </button>
                  ) : href ? (
                    <a
                      className={openPlatformClassName(namespace, "developer-portal-shell", "navigation-link")}
                      href={href}
                      aria-current={isCurrent ? "page" : undefined}
                      onClick={(event) => handleNavigate(item, event)}
                    >
                      {content}
                    </a>
                  ) : (
                    <button
                      className={openPlatformClassName(namespace, "developer-portal-shell", "navigation-button")}
                      type="button"
                      aria-current={isCurrent ? "page" : undefined}
                      onClick={(event) => handleNavigate(item, event)}
                    >
                      {content}
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        </nav>
      )}
      <main
        id={mainId}
        className={openPlatformClassName(namespace, "developer-portal-shell", "main")}
        aria-labelledby={headingId}
        tabIndex={-1}
      >
        {children}
      </main>
      {footer !== undefined && footer !== null && (
        <footer className={openPlatformClassName(namespace, "developer-portal-shell", "footer")}>{footer}</footer>
      )}
    </div>
  );
}
