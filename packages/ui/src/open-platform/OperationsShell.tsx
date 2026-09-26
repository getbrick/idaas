import { useId, type MouseEvent, type ReactNode } from "react";
import type {
  DeveloperPortalNavigationItem,
  OpenPlatformErrorValue,
  OpenPlatformOperationsNavigationItem,
} from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  sanitizeOpenPlatformHref,
  type OpenPlatformClassNamespaceProps,
} from "./theme.js";
import { getOpenPlatformPublicText } from "./utils.js";
import { EmptyState, ErrorState, LoadingState } from "./states.js";

export type OpenPlatformOperationsNavigateEvent = MouseEvent<HTMLAnchorElement | HTMLButtonElement>;

export interface OpenPlatformOperationsShellProps extends OpenPlatformClassNamespaceProps {
  title?: string;
  productName?: ReactNode;
  description?: ReactNode;
  navigation?: readonly OpenPlatformOperationsNavigationItem[];
  navigationLabel?: string;
  activeItemId?: string;
  onNavigate?: (item: OpenPlatformOperationsNavigationItem, event: OpenPlatformOperationsNavigateEvent) => void;
  headerActions?: ReactNode;
  footer?: ReactNode;
  busy?: boolean;
  loading?: boolean;
  isLoading?: boolean;
  error?: OpenPlatformErrorValue;
  empty?: boolean;
  state?: OpenPlatformOperationsStateName;
  status?: OpenPlatformOperationsStateName;
  onRetry?: () => void;
  emptyTitle?: string;
  emptyMessage?: string;
  errorTitle?: string;
  loadingLabel?: string;
  retryLabel?: string;
  children?: ReactNode;
}

export type OpenPlatformOperationsShellNavigationItem = DeveloperPortalNavigationItem;

export type OpenPlatformOperationsStateName = "loading" | "error" | "empty";

export interface OpenPlatformOperationsStateProps extends OpenPlatformClassNamespaceProps {
  state?: OpenPlatformOperationsStateName;
  status?: OpenPlatformOperationsStateName;
  loading?: boolean;
  isLoading?: boolean;
  error?: OpenPlatformErrorValue;
  empty?: boolean;
  onRetry?: () => void;
  emptyTitle?: string;
  emptyMessage?: string;
  errorTitle?: string;
  loadingLabel?: string;
  retryLabel?: string;
  children?: ReactNode;
}

export interface OpenPlatformOperationsLoadingStateProps extends OpenPlatformClassNamespaceProps {
  label?: string;
}

export interface OpenPlatformOperationsErrorStateProps extends OpenPlatformClassNamespaceProps {
  error?: OpenPlatformErrorValue;
  title?: string;
  retryLabel?: string;
  onRetry?: () => void;
}

export interface OpenPlatformOperationsEmptyStateProps extends OpenPlatformClassNamespaceProps {
  title?: string;
  message?: string;
  children?: ReactNode;
}

export function OpenPlatformOperationsShell({
  title,
  productName,
  description,
  navigation,
  navigationLabel,
  activeItemId,
  onNavigate,
  headerActions,
  footer,
  busy,
  loading = false,
  isLoading: isLoadingProp,
  error,
  empty = false,
  state,
  status,
  onRetry,
  emptyTitle,
  emptyMessage,
  errorTitle,
  loadingLabel,
  retryLabel,
  children,
  className,
  ...namespaceProps
}: OpenPlatformOperationsShellProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const headingId = useId();
  const mainId = useId();
  const shellTitle = getOpenPlatformPublicText(title, 256) ?? "Open platform operations";
  const navLabel = getOpenPlatformPublicText(navigationLabel, 128) ?? "Open platform operations navigation";
  const skipLabel = "Skip to content";
  const isLoading = isLoadingProp ?? loading;
  const isBusy = busy ?? isLoading;

  function handleNavigate(item: OpenPlatformOperationsNavigationItem, event: OpenPlatformOperationsNavigateEvent) {
    if (item.disabled) {
      event.preventDefault();
      return;
    }
    item.onSelect?.(item);
    onNavigate?.(item, event);
  }

  const content = children === undefined && error == null && !isLoading && !empty && state === undefined && status === undefined
    ? <OpenPlatformOperationsEmptyState classNamespace={namespace} title={emptyTitle} message={emptyMessage} />
    : (
      <OpenPlatformOperationsState
        state={state}
        status={status}
        loading={isLoading}
        error={error}
        empty={empty}
        onRetry={onRetry}
        emptyTitle={emptyTitle}
        emptyMessage={emptyMessage}
        errorTitle={errorTitle}
        loadingLabel={loadingLabel}
        retryLabel={retryLabel}
        classNamespace={namespace}
      >
        {children}
      </OpenPlatformOperationsState>
    );

  return (
    <div
      className={openPlatformClassNames(openPlatformClassName(namespace, "operations-shell"), className)}
      data-open-platform-operations-shell=""
      data-open-platform-shell=""
      aria-busy={isBusy || undefined}
    >
      <a className={openPlatformClassName(namespace, "operations-shell", "skip-link")} href={`#${mainId}`}>
        {skipLabel}
      </a>
      <header className={openPlatformClassName(namespace, "operations-shell", "header")}>
        <div className={openPlatformClassName(namespace, "operations-shell", "heading")}>
          {productName !== undefined && productName !== null && (
            <div className={openPlatformClassName(namespace, "operations-shell", "product-name")}>{productName}</div>
          )}
          <h1 id={headingId} className={openPlatformClassName(namespace, "operations-shell", "title")}>
            {shellTitle}
          </h1>
          {description !== undefined && description !== null && (
            <div className={openPlatformClassName(namespace, "operations-shell", "description")}>{description}</div>
          )}
        </div>
        {headerActions !== undefined && headerActions !== null && (
          <div
            className={openPlatformClassName(namespace, "operations-shell", "header-actions")}
            role="group"
            aria-label="Open platform operations actions"
          >
            {headerActions}
          </div>
        )}
      </header>
      {navigation && navigation.length > 0 && (
        <nav className={openPlatformClassName(namespace, "operations-shell", "navigation")} aria-label={navLabel}>
          <ul className={openPlatformClassName(namespace, "operations-shell", "navigation-list")}>
            {navigation.map((item, index) => {
              const itemLabel = getOpenPlatformPublicText(item.label, 128) ?? getOpenPlatformPublicText(item.id, 128) ?? "Navigation item";
              const href = item.href ? sanitizeOpenPlatformHref(item.href) : undefined;
              const contentNode = (
                <>
                  <span>{itemLabel}</span>
                  {item.badge !== undefined && item.badge !== null && (
                    <span className={openPlatformClassName(namespace, "operations-shell", "navigation-badge")}>{item.badge}</span>
                  )}
                </>
              );
              return (
                <li className={openPlatformClassName(namespace, "operations-shell", "navigation-item")} key={`${item.id}-${index}`}>
                  {item.disabled ? (
                    <button
                      className={openPlatformClassName(namespace, "operations-shell", "navigation-button")}
                      type="button"
                      disabled
                      aria-current={activeItemId === item.id ? "page" : undefined}
                    >
                      {contentNode}
                    </button>
                  ) : href ? (
                    <a
                      className={openPlatformClassName(namespace, "operations-shell", "navigation-link")}
                      href={href}
                      aria-current={activeItemId === item.id ? "page" : undefined}
                      onClick={(event) => handleNavigate(item, event)}
                    >
                      {contentNode}
                    </a>
                  ) : (
                    <button
                      className={openPlatformClassName(namespace, "operations-shell", "navigation-button")}
                      type="button"
                      aria-current={activeItemId === item.id ? "page" : undefined}
                      onClick={(event) => handleNavigate(item, event)}
                    >
                      {contentNode}
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
        className={openPlatformClassName(namespace, "operations-shell", "main")}
        aria-labelledby={headingId}
        tabIndex={-1}
      >
        {content}
      </main>
      {footer !== undefined && footer !== null && (
        <footer className={openPlatformClassName(namespace, "operations-shell", "footer")}>{footer}</footer>
      )}
    </div>
  );
}

export function OpenPlatformOperationsLoadingState({ label, ...props }: OpenPlatformOperationsLoadingStateProps) {
  return <LoadingState label={label ?? "Loading operations"} {...props} />;
}

export function OpenPlatformOperationsErrorState({ error, title, retryLabel, onRetry, ...props }: OpenPlatformOperationsErrorStateProps) {
  return <ErrorState error={error} title={title ?? "Unable to load operations"} retryLabel={retryLabel} onRetry={onRetry} {...props} />;
}

export function OpenPlatformOperationsEmptyState({ title, message, children, ...props }: OpenPlatformOperationsEmptyStateProps) {
  return <EmptyState title={title ?? "Nothing to show"} message={message ?? "No records are available."} {...props}>{children}</EmptyState>;
}

export function OpenPlatformOperationsState({
  state,
  status,
  loading = false,
  isLoading: isLoadingProp,
  error,
  empty = false,
  onRetry,
  emptyTitle,
  emptyMessage,
  errorTitle,
  loadingLabel,
  retryLabel,
  children,
  ...namespaceProps
}: OpenPlatformOperationsStateProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const isLoading = isLoadingProp ?? loading;
  const activeState: OpenPlatformOperationsStateName | undefined = error != null
    ? "error"
    : isLoading
      ? "loading"
      : empty
        ? "empty"
        : state ?? status;
  if (activeState === "error") {
    return (
      <OpenPlatformOperationsErrorState
        error={error}
        title={errorTitle}
        retryLabel={retryLabel}
        onRetry={onRetry}
        classNamespace={namespace}
      />
    );
  }
  if (activeState === "loading") {
    return <OpenPlatformOperationsLoadingState label={loadingLabel} classNamespace={namespace} />;
  }
  if (activeState === "empty") {
    return (
      <OpenPlatformOperationsEmptyState
        title={emptyTitle}
        message={emptyMessage}
        classNamespace={namespace}
      />
    );
  }
  return <>{children}</>;
}

export const OperationsShell = OpenPlatformOperationsShell;
export const OpenPlatformOperations = OpenPlatformOperationsShell;
export const OperationsLoadingState = OpenPlatformOperationsLoadingState;
export const OperationsErrorState = OpenPlatformOperationsErrorState;
export const OperationsEmptyState = OpenPlatformOperationsEmptyState;
export const OperationsState = OpenPlatformOperationsState;
export const OperationsLoading = OpenPlatformOperationsLoadingState;
export const OperationsError = OpenPlatformOperationsErrorState;
export const OperationsEmpty = OpenPlatformOperationsEmptyState;
export const OpenPlatformOperationsLoading = OpenPlatformOperationsLoadingState;
export const OpenPlatformOperationsError = OpenPlatformOperationsErrorState;
export const OpenPlatformOperationsEmpty = OpenPlatformOperationsEmptyState;
export const OpenPlatformOperationsListState = OpenPlatformOperationsState;
