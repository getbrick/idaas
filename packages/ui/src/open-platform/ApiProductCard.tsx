import { useId, type MouseEvent, type ReactNode } from "react";
import { AppLifecycleStatusBadge } from "./AppLifecycleStatusBadge.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  sanitizeOpenPlatformHref,
  type OpenPlatformClassNamespaceProps,
} from "./theme.js";
import type { ApiProduct, AppLifecycleStatus } from "./types.js";
import { getOpenPlatformText } from "./utils.js";

export type ApiProductCardOpenEvent = MouseEvent<HTMLAnchorElement | HTMLButtonElement>;

export interface ApiProductCardProps<TProduct extends ApiProduct = ApiProduct> extends OpenPlatformClassNamespaceProps {
  product: TProduct;
  description?: ReactNode;
  status?: AppLifecycleStatus;
  href?: string | null;
  openLabel?: string;
  disabled?: boolean;
  actions?: ReactNode | ((product: TProduct) => ReactNode);
  footer?: ReactNode;
  onOpen?: (product: TProduct, event: ApiProductCardOpenEvent) => void;
}

export function ApiProductCard<TProduct extends ApiProduct = ApiProduct>({
  product,
  description,
  status,
  href,
  openLabel,
  disabled = false,
  actions,
  footer,
  onOpen,
  className,
  ...namespaceProps
}: ApiProductCardProps<TProduct>) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const headingId = useId();
  const productName = getOpenPlatformText(product.name, 256) ?? "Untitled API";
  const productId = getOpenPlatformText(product.id, 256) ?? "unknown";
  const productDescription = description === undefined ? getOpenPlatformText(product.description, 2048) : description;
  const category = getOpenPlatformText(product.category, 128);
  const version = typeof product.version === "number" && Number.isFinite(product.version)
    ? String(product.version)
    : getOpenPlatformText(product.version, 128);
  const lifecycleStatus = status ?? product.status;
  const safeHref = href === undefined ? product.href : href;
  const normalizedHref = safeHref ? sanitizeOpenPlatformHref(safeHref) : undefined;
  const actionLabel = getOpenPlatformText(openLabel, 128) ?? "Open API";
  const actionContent = (
    <>
      <span>{actionLabel}</span>
      <span aria-hidden="true"> →</span>
    </>
  );

  function handleOpen(event: ApiProductCardOpenEvent) {
    onOpen?.(product, event);
  }

  const productActions = typeof actions === "function" ? actions(product) : actions;
  const hasFooter = productActions !== undefined && productActions !== null || footer !== undefined && footer !== null;
  const hasOpenAction = normalizedHref !== undefined || onOpen !== undefined;

  return (
    <article
      className={openPlatformClassNames(openPlatformClassName(namespace, "api-product-card"), className)}
      data-api-product-id={productId}
      aria-labelledby={headingId}
      aria-disabled={disabled || undefined}
    >
      <header className={openPlatformClassName(namespace, "api-product-card", "header")}>
        <h3 id={headingId} className={openPlatformClassName(namespace, "api-product-card", "title")}>
          {productName}
        </h3>
        {lifecycleStatus !== undefined && <AppLifecycleStatusBadge status={lifecycleStatus} classNamespace={namespace} />}
      </header>
      {productDescription !== undefined && productDescription !== null && (
        <div className={openPlatformClassName(namespace, "api-product-card", "description")}>{productDescription}</div>
      )}
      {(category || version) && (
        <dl className={openPlatformClassName(namespace, "api-product-card", "metadata")}>
          {category && (
            <>
              <dt>Category</dt>
              <dd>{category}</dd>
            </>
          )}
          {version && (
            <>
              <dt>Version</dt>
              <dd>{version}</dd>
            </>
          )}
        </dl>
      )}
      {hasOpenAction && (
        <div className={openPlatformClassName(namespace, "api-product-card", "actions")}>
          {disabled ? (
            <button
              className={openPlatformClassName(namespace, "api-product-card", "open-button")}
              type="button"
              disabled
            >
              {actionContent}
            </button>
          ) : normalizedHref ? (
            <a
              className={openPlatformClassName(namespace, "api-product-card", "open-link")}
              href={normalizedHref}
              onClick={handleOpen}
            >
              {actionContent}
            </a>
          ) : (
            <button
              className={openPlatformClassName(namespace, "api-product-card", "open-button")}
              type="button"
              onClick={handleOpen}
            >
              {actionContent}
            </button>
          )}
        </div>
      )}
      {hasFooter && (
        <footer className={openPlatformClassName(namespace, "api-product-card", "footer")}>
          {productActions}
          {footer}
        </footer>
      )}
    </article>
  );
}
