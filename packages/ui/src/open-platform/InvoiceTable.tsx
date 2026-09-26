import { useId, type ReactNode } from "react";
import { OpenPlatformListState } from "./OpenPlatformListState.js";
import { OpenPlatformPagination } from "./OpenPlatformPagination.js";
import type {
  OpenPlatformInvoice,
  OpenPlatformListBaseProps,
  OpenPlatformPage,
  OpenPlatformPaginationState,
} from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
} from "./theme.js";
import {
  getOpenPlatformAmount,
  getOpenPlatformDate,
  getOpenPlatformPublicText,
  getOpenPlatformSafeText,
  getOpenPlatformStatusText,
  maskOpenPlatformAddress,
  maskOpenPlatformBankAccount,
  maskOpenPlatformPhone,
  maskOpenPlatformSecretReference,
  maskOpenPlatformSettlementReference,
} from "./utils.js";

export interface InvoiceTableProps extends OpenPlatformListBaseProps {
  invoices?: readonly OpenPlatformInvoice[];
  items?: readonly OpenPlatformInvoice[];
  data?: readonly OpenPlatformInvoice[];
  records?: readonly OpenPlatformInvoice[];
  pagination?: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformInvoice>;
  cursor?: string;
  nextCursor?: string;
  previousCursor?: string;
  hasMore?: boolean;
  page?: number;
  pageSize?: number;
  total?: number;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  hasNext?: boolean;
  hasPrevious?: boolean;
  onCursorChange?: (cursor?: string) => void;
  onNext?: () => void;
  onPrevious?: () => void;
  onNextPage?: () => void;
  onPreviousPage?: () => void;
  onLoadMore?: () => void;
  onPageChange?: (page: number) => void;
  renderActions?: (invoice: OpenPlatformInvoice) => ReactNode;
  paginationLabel?: string;
  previousLabel?: string;
  nextLabel?: string;
}

export function InvoiceTable({
  invoices,
  items,
  data,
  records,
  pagination,
  cursor,
  nextCursor,
  previousCursor,
  hasMore,
  page,
  pageSize,
  total,
  hasNextPage,
  hasPreviousPage,
  hasNext,
  hasPrevious,
  onCursorChange,
  onNext,
  onPrevious,
  onNextPage,
  onPreviousPage,
  onLoadMore,
  onPageChange,
  renderActions,
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
  className,
  ...namespaceProps
}: InvoiceTableProps) {
  const headingId = useId();
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const isLoading = isLoadingProp ?? loading ?? false;
  const rows = invoices ?? items ?? data ?? records ?? pageItems(pagination) ?? [];
  const listTitle = getOpenPlatformPublicText(title, 256) ?? "Invoices";
  const tableCaption = typeof caption === "string" ? getOpenPlatformPublicText(caption, 512) ?? listTitle : caption ?? listTitle;
  const hasActions = renderActions !== undefined;
  const columnCount = hasActions ? 9 : 8;
  const hasPagination = pagination !== undefined || cursor !== undefined || nextCursor !== undefined || previousCursor !== undefined || hasMore !== undefined || page !== undefined || pageSize !== undefined || total !== undefined || hasNextPage !== undefined || hasPreviousPage !== undefined || onCursorChange !== undefined || onNext !== undefined || onPrevious !== undefined || onLoadMore !== undefined || onPageChange !== undefined || hasNext !== undefined || hasPrevious !== undefined || onNextPage !== undefined || onPreviousPage !== undefined;

  return (
    <section
      className={openPlatformClassNames(openPlatformClassName(namespace, "invoice-table"), className)}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-open-platform-list="billing-invoices"
      data-open-platform-resource="billing-invoices"
    >
      <header className={openPlatformClassName(namespace, "invoice-table", "header")}>
        <h2 id={headingId} className={openPlatformClassName(namespace, "invoice-table", "heading")}>
          {listTitle}
        </h2>
        {actions !== undefined && actions !== null && (
          <div className={openPlatformClassName(namespace, "invoice-table", "actions")}>{actions}</div>
        )}
      </header>
      <table className={openPlatformClassName(namespace, "invoice-table", "table")} aria-busy={isLoading || undefined}>
        <caption className={openPlatformClassName(namespace, "invoice-table", "caption")}>{tableCaption}</caption>
        <thead>
          <tr>
            <th scope="col">Invoice</th>
            <th scope="col">Status</th>
            <th scope="col">Period</th>
            <th scope="col">Total</th>
            <th scope="col">Buyer</th>
            <th scope="col">Bank account</th>
            <th scope="col">Contact</th>
            <th scope="col">References</th>
            {hasActions && <th scope="col">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {error != null || isLoading || rows.length === 0 ? (
            <OpenPlatformListState
              classNamespace={namespace}
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
            rows.map((invoice, index) => {
              const metadata = getMetadata(invoice);
              const buyer = getBuyer(invoice);
              const invoiceId = getOpenPlatformSafeText(invoice.invoiceId ?? invoice.invoice_id ?? invoice.invoiceNumber ?? invoice.invoiceNumberText ?? invoice.id, 256) ?? "Unknown invoice";
              const status = getOpenPlatformStatusText(invoice.status);
              const periodStart = getOpenPlatformDate(invoice.periodStart ?? invoice.period_start);
              const periodEnd = getOpenPlatformDate(invoice.periodEnd ?? invoice.period_end);
              const totalValue = getOpenPlatformAmount(invoice.total ?? invoice.totalAmount ?? invoice.amount ?? invoice.subtotal, invoice.currency);
              const lineSummary = (invoice.lines ?? [])
                .map((line) => getOpenPlatformPublicText(line.description, 256))
                .filter((line): line is string => Boolean(line))
                .slice(0, 3)
                .join(", ");
              const buyerName = getOpenPlatformSafeText(metadata.buyerName ?? metadata.buyer_name ?? invoice.buyerName ?? invoice.buyer_name ?? invoice.customerName ?? buyer.name ?? buyer.displayName, 256) ?? "—";
              const bankAccount = metadata.buyerBankAccount ?? metadata.buyer_bank_account ?? metadata.bankAccount ?? metadata.bankAccountNumber ?? invoice.buyerBankAccount ?? invoice.buyer_bank_account ?? invoice.bankAccount ?? invoice.bankAccountNumber ?? buyer.bankAccount ?? buyer.bankAccountNumber;
              const address = metadata.buyerAddress ?? metadata.buyer_address ?? metadata.address ?? invoice.buyerAddress ?? invoice.buyer_address ?? invoice.billingAddress ?? invoice.address ?? buyer.address;
              const phone = metadata.buyerPhone ?? metadata.buyer_phone ?? metadata.phone ?? invoice.buyerPhone ?? invoice.buyer_phone ?? invoice.phone ?? buyer.phone;
              const settlementReference = metadata.settlementReference ?? metadata.settlement_reference ?? metadata.settlementRef ?? invoice.settlementReference ?? invoice.settlement_reference ?? invoice.settlementRef ?? buyer.settlementReference;
              const secretReference = metadata.secretReference ?? metadata.secret_reference ?? invoice.secretReference ?? invoice.secret_reference ?? invoice.secretRef ?? invoice.secret_ref ?? buyer.secretReference;
              const contactParts = [
                phone === undefined || phone === null ? undefined : maskOpenPlatformPhone(phone),
                address === undefined || address === null ? undefined : maskOpenPlatformAddress(address),
              ].filter((part): part is string => Boolean(part));
              const contact = contactParts.length > 0 ? contactParts.join(" · ") : "—";
              const references = settlementReference == null && secretReference == null
                ? "—"
                : `${maskOpenPlatformSettlementReference(settlementReference)} · ${maskOpenPlatformSecretReference(secretReference)}`;
              return (
                <tr key={invoice.id || `invoice-${index}`} className={openPlatformClassName(namespace, "invoice-table", "row")}>
                  <td className={openPlatformClassName(namespace, "invoice-table", "cell")}>
                    <span className={openPlatformClassName(namespace, "invoice-table", "invoice-id")}>{invoiceId}</span>
                  </td>
                  <td className={openPlatformClassName(namespace, "invoice-table", "cell")}>
                    <span data-invoice-status={status}>{status}</span>
                  </td>
                  <td className={openPlatformClassName(namespace, "invoice-table", "cell")}>
                    {periodStart.dateTime || periodEnd.dateTime ? `${periodStart.label} – ${periodEnd.label}` : "—"}
                  </td>
                  <td className={openPlatformClassName(namespace, "invoice-table", "cell")}>
                    <span>{totalValue}</span>
                    {lineSummary && <span className={openPlatformClassName(namespace, "invoice-table", "line-summary")}>{lineSummary}</span>}
                  </td>
                  <td className={openPlatformClassName(namespace, "invoice-table", "cell")}>{buyerName}</td>
                  <td className={openPlatformClassName(namespace, "invoice-table", "cell")}>
                    <span data-bank-account="masked">{maskOpenPlatformBankAccount(bankAccount)}</span>
                  </td>
                  <td className={openPlatformClassName(namespace, "invoice-table", "cell")}>
                    <span data-invoice-contact="masked">
                      {contact}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, "invoice-table", "cell")}>
                    <span data-invoice-references="masked">
                      {references}
                    </span>
                  </td>
                  {hasActions && <td className={openPlatformClassName(namespace, "invoice-table", "cell")}>{renderActions?.(invoice)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {hasPagination && (
        <OpenPlatformPagination
          block="invoice-table"
          pagination={pagination}
          cursor={cursor}
          nextCursor={nextCursor}
          previousCursor={previousCursor}
          hasMore={hasMore}
          page={page}
          pageSize={pageSize}
          total={total}
          hasNextPage={hasNextPage}
          hasPreviousPage={hasPreviousPage}
          hasNext={hasNext}
          hasPrevious={hasPrevious}
          onCursorChange={onCursorChange}
          onNext={onNext}
          onPrevious={onPrevious}
          onNextPage={onNextPage}
          onPreviousPage={onPreviousPage}
          onLoadMore={onLoadMore}
          onPageChange={onPageChange}
          paginationLabel={paginationLabel}
          previousLabel={previousLabel}
          nextLabel={nextLabel}
          classNamespace={namespace}
        />
      )}
    </section>
  );
}

export const BillingInvoiceTable = InvoiceTable;
export const InvoicesTable = InvoiceTable;
export const OpenPlatformInvoiceTable = InvoiceTable;

function getBuyer(invoice: OpenPlatformInvoice): Record<string, unknown> {
  return invoice.buyer !== null && typeof invoice.buyer === "object" && !Array.isArray(invoice.buyer)
    ? invoice.buyer as Record<string, unknown>
    : {};
}

function getMetadata(invoice: OpenPlatformInvoice): Record<string, unknown> {
  const value = invoice.mainlandChina ?? invoice.mainland_china ?? invoice.invoiceMetadata ?? invoice.metadata;
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function pageItems(
  pagination: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformInvoice> | undefined,
): readonly OpenPlatformInvoice[] | undefined {
  return pagination !== undefined && "items" in pagination ? pagination.items : undefined;
}
