import { useId, type ReactNode } from "react";
import { OpenPlatformListState } from "./OpenPlatformListState.js";
import { OpenPlatformPagination } from "./OpenPlatformPagination.js";
import type {
  OpenPlatformComplianceDataAsset,
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
  getOpenPlatformBooleanText,
  getOpenPlatformComplianceCount,
  getOpenPlatformPublicText,
  getOpenPlatformSafeEvidenceSummary,
  getOpenPlatformSafeTextList,
  getOpenPlatformStatusText,
} from "./utils.js";

export interface ComplianceDataAssetListProps extends OpenPlatformListBaseProps {
  dataAssets?: readonly OpenPlatformComplianceDataAsset[];
  assets?: readonly OpenPlatformComplianceDataAsset[];
  items?: readonly OpenPlatformComplianceDataAsset[];
  data?: readonly OpenPlatformComplianceDataAsset[];
  records?: readonly OpenPlatformComplianceDataAsset[];
  pagination?: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformComplianceDataAsset>;
  cursor?: string;
  nextCursor?: string;
  previousCursor?: string;
  hasMore?: boolean;
  nextSequence?: number;
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
  renderActions?: (asset: OpenPlatformComplianceDataAsset) => ReactNode;
  renderEvidence?: (asset: OpenPlatformComplianceDataAsset) => ReactNode;
  paginationLabel?: string;
  previousLabel?: string;
  nextLabel?: string;
}

const DATA_ASSET_BLOCK = "compliance-data-asset-list";
const DATA_ASSET_COLUMN_COUNT = 9;

export function ComplianceDataAssetList({
  dataAssets,
  assets,
  items,
  data,
  records,
  pagination,
  cursor,
  nextCursor,
  previousCursor,
  hasMore,
  nextSequence,
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
  renderEvidence,
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
}: ComplianceDataAssetListProps) {
  const headingId = useId();
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const isLoading = isLoadingProp ?? loading ?? false;
  const rows = dataAssets ?? assets ?? items ?? data ?? records ?? pageItems(pagination) ?? [];
  const listTitle = getOpenPlatformPublicText(title, 256) ?? "Data assets";
  const tableCaption = typeof caption === "string" ? getOpenPlatformPublicText(caption, 512) ?? listTitle : caption ?? listTitle;
  const hasActions = renderActions !== undefined;
  const columnCount = hasActions ? DATA_ASSET_COLUMN_COUNT + 1 : DATA_ASSET_COLUMN_COUNT;
  const hasPagination = pagination !== undefined || cursor !== undefined || nextCursor !== undefined || previousCursor !== undefined || hasMore !== undefined || nextSequence !== undefined || page !== undefined || pageSize !== undefined || total !== undefined || hasNextPage !== undefined || hasPreviousPage !== undefined || onCursorChange !== undefined || onNext !== undefined || onPrevious !== undefined || onLoadMore !== undefined || onPageChange !== undefined || hasNext !== undefined || hasPrevious !== undefined || onNextPage !== undefined || onPreviousPage !== undefined;

  return (
    <section
      className={openPlatformClassNames(openPlatformClassName(namespace, DATA_ASSET_BLOCK), className)}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-open-platform-list="compliance-data-assets"
      data-open-platform-resource="compliance-data-assets"
    >
      <header className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "header")}>
        <h2 id={headingId} className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "heading")}>
          {listTitle}
        </h2>
        {actions !== undefined && actions !== null && (
          <div className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "actions")}>{actions}</div>
        )}
      </header>
      <table className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "table")} aria-busy={isLoading || undefined}>
        <caption className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "caption")}>{tableCaption}</caption>
        <thead>
          <tr>
            <th scope="col">Asset</th>
            <th scope="col">Status</th>
            <th scope="col">Classification</th>
            <th scope="col">Personal data</th>
            <th scope="col">Legal basis</th>
            <th scope="col">Retention</th>
            <th scope="col">Residency</th>
            <th scope="col">Cross-border</th>
            <th scope="col">Evidence</th>
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
            rows.map((asset, index) => {
              const status = getOpenPlatformStatusText(asset.status);
              const classification = getOpenPlatformStatusText(asset.classification, "Unclassified");
              const retentionPolicyId = getOpenPlatformPublicText(asset.retentionPolicyId, 256);
              const retentionDays = getOpenPlatformComplianceCount(asset.retentionDays);
              const residency = getOpenPlatformSafeTextList(asset.residencyRegions, 6);
              const evidence = getOpenPlatformSafeEvidenceSummary(asset.evidence, 3);
              return (
                <tr key={asset.id || `data-asset-${index}`} className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "row")}>
                  <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>
                    <span className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "name")}>
                      {getOpenPlatformPublicText(asset.name, 256) ?? "Unnamed data asset"}
                    </span>
                    <span className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "asset-code")}>
                      {getOpenPlatformPublicText(asset.code, 128) ?? "—"}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>
                    <span
                      className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "status")}
                      data-data-asset-status={status}
                    >
                      {status}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>{classification}</td>
                  <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>
                    <span
                      data-personal-data={getOpenPlatformBooleanText(asset.personalData)}
                      data-sensitive-personal-data={getOpenPlatformBooleanText(asset.sensitivePersonalData)}
                    >
                      {getOpenPlatformBooleanText(asset.personalData)}
                      {asset.sensitivePersonalData === true ? " · Sensitive" : ""}
                    </span>
                  </td>
                  <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>
                    {getOpenPlatformPublicText(asset.legalBasis, 128) ?? "—"}
                  </td>
                  <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>
                    {retentionDays === undefined
                      ? retentionPolicyId ?? "—"
                      : `${retentionPolicyId === undefined ? "Policy" : retentionPolicyId} · ${retentionDays} days`}
                  </td>
                  <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>
                    {residency.length > 0 ? residency.join(", ") : "—"}
                  </td>
                  <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>
                    {getOpenPlatformBooleanText(asset.crossBorder)}
                  </td>
                  <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>
                    {renderEvidence
                      ? renderEvidence(asset)
                      : evidence.length === 0
                        ? "—"
                        : evidence.map((item, position) => (
                            <span
                              key={`${item.kind}-${position}`}
                              className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "evidence")}
                              data-evidence-kind={item.kind}
                            >
                              {item.kind}
                              <span data-evidence-reference="masked">{item.reference}</span>
                              {item.recordedAt === undefined ? null : (
                                <time dateTime={item.recordedAt}>{item.recordedAt}</time>
                              )}
                            </span>
                          ))}
                  </td>
                  {hasActions && <td className={openPlatformClassName(namespace, DATA_ASSET_BLOCK, "cell")}>{renderActions?.(asset)}</td>}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      {hasPagination && (
        <OpenPlatformPagination
          block={DATA_ASSET_BLOCK}
          pagination={pagination}
          cursor={cursor}
          nextCursor={nextCursor}
          previousCursor={previousCursor}
          hasMore={hasMore}
          nextSequence={nextSequence}
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

export const OpenPlatformComplianceDataAssetList = ComplianceDataAssetList;
export const DataAssetList = ComplianceDataAssetList;
export const ComplianceDataAssetsTable = ComplianceDataAssetList;

function pageItems(
  pagination: OpenPlatformPaginationState | OpenPlatformPage<OpenPlatformComplianceDataAsset> | undefined,
): readonly OpenPlatformComplianceDataAsset[] | undefined {
  return pagination !== undefined && "items" in pagination ? pagination.items : undefined;
}
