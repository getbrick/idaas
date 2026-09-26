import { useId, type MouseEvent, type ReactNode } from "react";
import type { OpenPlatformMarketplaceListing } from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  sanitizeOpenPlatformHref,
  type OpenPlatformClassNamespaceProps,
} from "./theme.js";
import { getOpenPlatformDate, getOpenPlatformSafeText, getOpenPlatformStatusText } from "./utils.js";

export type MarketplaceListingCardOpenEvent = MouseEvent<HTMLAnchorElement | HTMLButtonElement>;

export interface MarketplaceListingCardProps<TListing extends OpenPlatformMarketplaceListing = OpenPlatformMarketplaceListing> extends OpenPlatformClassNamespaceProps {
  listing: TListing;
  description?: ReactNode;
  href?: string | null;
  openLabel?: string;
  disabled?: boolean;
  actions?: ReactNode | ((listing: TListing) => ReactNode);
  footer?: ReactNode;
  onOpen?: (listing: TListing, event: MarketplaceListingCardOpenEvent) => void;
}

export function MarketplaceListingCard<TListing extends OpenPlatformMarketplaceListing = OpenPlatformMarketplaceListing>({
  listing,
  description,
  href,
  openLabel,
  disabled = false,
  actions,
  footer,
  onOpen,
  className,
  ...namespaceProps
}: MarketplaceListingCardProps<TListing>) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const headingId = useId();
  const title = getOpenPlatformSafeText(listing.title ?? listing.name ?? listing.listingName ?? listing.productName, 256) ?? "Untitled listing";
  const listingId = getOpenPlatformSafeText(listing.id, 256) ?? "unknown";
  const listingDescription = description === undefined ? getOpenPlatformSafeText(listing.description, 2048) : description;
  const status = getOpenPlatformStatusText(listing.status);
  const suppliedHref = href === undefined ? listing.href : href;
  const safeHref = suppliedHref === undefined || suppliedHref === null ? undefined : sanitizeOpenPlatformHref(suppliedHref);
  const normalizedHref = safeHref;
  const actionLabel = getOpenPlatformSafeText(openLabel, 128) ?? "Open listing";
  const priceIds = safeIds(listing.priceIds ?? listing.price_ids);
  const commissionRuleIds = safeIds(listing.commissionRuleIds ?? listing.commission_rule_ids);
  const published = listing.publishedAt ? getOpenPlatformDate(listing.publishedAt) : undefined;
  const productId = getOpenPlatformSafeText(listing.productId ?? listing.product_id, 256);
  const partnerId = getOpenPlatformSafeText(listing.partnerAccountId ?? listing.partner_account_id ?? listing.partnerId, 256);
  const listingActions = typeof actions === "function" ? actions(listing) : actions;
  const hasFooter = listingActions !== undefined && listingActions !== null || footer !== undefined && footer !== null;
  const hasOpenAction = normalizedHref !== undefined || onOpen !== undefined;
  const actionContent = (
    <>
      <span>{actionLabel}</span>
      <span aria-hidden="true"> →</span>
    </>
  );

  function handleOpen(event: MarketplaceListingCardOpenEvent) {
    onOpen?.(listing, event);
  }

  return (
    <article
      className={openPlatformClassNames(openPlatformClassName(namespace, "marketplace-listing-card"), className)}
      data-marketplace-listing-id={listingId}
      data-open-platform-resource="marketplace-listing"
      aria-labelledby={headingId}
      aria-disabled={disabled || undefined}
    >
      <header className={openPlatformClassName(namespace, "marketplace-listing-card", "header")}>
        <h3 id={headingId} className={openPlatformClassName(namespace, "marketplace-listing-card", "title")}>
          {title}
        </h3>
        <span
          className={openPlatformClassName(namespace, "marketplace-listing-card", "status")}
          data-listing-status={status}
        >
          {status}
        </span>
      </header>
      {listingDescription !== undefined && listingDescription !== null && (
        <div className={openPlatformClassName(namespace, "marketplace-listing-card", "description")}>{listingDescription}</div>
      )}
      <dl className={openPlatformClassName(namespace, "marketplace-listing-card", "metadata")}>
        {productId && (
          <>
            <dt>Product</dt>
            <dd>{productId}</dd>
          </>
        )}
        {partnerId && (
          <>
            <dt>Partner</dt>
            <dd>{partnerId}</dd>
          </>
        )}
        {priceIds.length > 0 && (
          <>
            <dt>Prices</dt>
            <dd>{priceIds.join(", ")}</dd>
          </>
        )}
        {commissionRuleIds.length > 0 && (
          <>
            <dt>Commission rules</dt>
            <dd>{commissionRuleIds.join(", ")}</dd>
          </>
        )}
        {published && (
          <>
            <dt>Published</dt>
            <dd>
              <time dateTime={published.dateTime}>{published.label}</time>
            </dd>
          </>
        )}
      </dl>
      {hasOpenAction && (
        <div className={openPlatformClassName(namespace, "marketplace-listing-card", "actions")}>
          {disabled ? (
            <button
              className={openPlatformClassName(namespace, "marketplace-listing-card", "open-button")}
              type="button"
              disabled
            >
              {actionContent}
            </button>
          ) : normalizedHref ? (
            <a
              className={openPlatformClassName(namespace, "marketplace-listing-card", "open-link")}
              href={normalizedHref}
              onClick={handleOpen}
            >
              {actionContent}
            </a>
          ) : (
            <button
              className={openPlatformClassName(namespace, "marketplace-listing-card", "open-button")}
              type="button"
              onClick={handleOpen}
            >
              {actionContent}
            </button>
          )}
        </div>
      )}
      {hasFooter && (
        <footer className={openPlatformClassName(namespace, "marketplace-listing-card", "footer")}>
          {listingActions}
          {footer}
        </footer>
      )}
    </article>
  );
}

export const MarketplaceCard = MarketplaceListingCard;
export const OpenPlatformMarketplaceListingCard = MarketplaceListingCard;

function safeIds(values: readonly string[] | undefined): string[] {
  return (values ?? []).map((value) => getOpenPlatformSafeText(value, 256)).filter((value): value is string => Boolean(value));
}
