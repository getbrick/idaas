import { useId } from "react";
import { EmptyState, ErrorState, LoadingState } from "./states.js";
import type {
  OpenPlatformComplianceReport,
  OpenPlatformListBaseProps,
} from "./types.js";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
} from "./theme.js";
import {
  getOpenPlatformComplianceCount,
  getOpenPlatformDate,
  getOpenPlatformPublicText,
  getOpenPlatformSafeCountBreakdown,
  getOpenPlatformSafeTextList,
  getOpenPlatformStatusText,
  OPEN_PLATFORM_REDACTED_VALUE,
  type OpenPlatformComplianceCountBreakdownSummary,
} from "./utils.js";

export interface ComplianceReportPanelProps extends OpenPlatformListBaseProps {
  report?: OpenPlatformComplianceReport | null;
  showGaps?: boolean;
  showLimitations?: boolean;
  emptyTitle?: string;
  emptyMessage?: string;
}

interface ComplianceReportSection {
  readonly key: string;
  readonly label: string;
  readonly source: string;
  readonly breakdowns: readonly string[];
  readonly metrics: readonly (readonly [string, string])[];
}

const REPORT_BLOCK = "compliance-report-panel";
const REPORT_SECTIONS: readonly ComplianceReportSection[] = [
  {
    key: "dataCatalog",
    label: "Data catalog",
    source: "dataCatalog",
    breakdowns: ["assets"],
    metrics: [
      ["Personal data assets", "personalDataAssets"],
      ["Sensitive personal data assets", "sensitivePersonalDataAssets"],
      ["Cross-border assets", "crossBorderAssets"],
    ],
  },
  {
    key: "consent",
    label: "Consent",
    source: "consent",
    breakdowns: ["records"],
    metrics: [
      ["Active subjects", "activeSubjects"],
      ["Withdrawn subjects", "withdrawnSubjects"],
      ["Withdrawn proof count", "withdrawnProofCount"],
    ],
  },
  {
    key: "privacyRequests",
    label: "Privacy requests",
    source: "privacyRequests",
    breakdowns: ["requests"],
    metrics: [
      ["Awaiting identity verification", "awaitingIdentityVerification"],
      ["Fulfilled within SLA", "fulfilledWithinSla"],
      ["SLA breached", "breached"],
      ["Oldest open (days)", "oldestOpenDays"],
    ],
  },
  {
    key: "retention",
    label: "Retention",
    source: "retention",
    breakdowns: ["policies", "executions"],
    metrics: [
      ["Records deleted", "recordsDeleted"],
      ["Records anonymized", "recordsAnonymized"],
    ],
  },
  {
    key: "crossBorder",
    label: "Cross-border",
    source: "crossBorder",
    breakdowns: ["assessments", "byRiskLevel"],
    metrics: [],
  },
  {
    key: "vendors",
    label: "Vendors",
    source: "vendors",
    breakdowns: ["vendors", "byRole", "assessment"],
    metrics: [],
  },
];

export function ComplianceReportPanel({
  report,
  showGaps = true,
  showLimitations = true,
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
}: ComplianceReportPanelProps) {
  const headingId = useId();
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const isLoading = isLoadingProp ?? loading ?? false;
  const panelTitle = getOpenPlatformPublicText(title, 256) ?? "Compliance report";
  const panelCaption = typeof caption === "string" ? getOpenPlatformPublicText(caption, 512) ?? panelTitle : caption;
  const hasReport = report !== undefined && report !== null && typeof report === "object";
  const generatedAt = getOpenPlatformDate(hasReport ? report?.generatedAt : undefined);
  const period = report?.period;
  const periodFrom = getOpenPlatformPublicText(period?.from, 64);
  const periodTo = getOpenPlatformPublicText(period?.to, 64);
  const contractVersion = getOpenPlatformComplianceCount(report?.contractVersion);
  const redactionApplies = report?.redaction?.applies === true;
  const redactionPlaceholder = getOpenPlatformPublicText(report?.redaction?.placeholder, 64) ?? OPEN_PLATFORM_REDACTED_VALUE;
  const gaps = hasReport && showGaps ? getOpenPlatformSafeGaps(report) : [];
  const limitations = hasReport && showLimitations ? getOpenPlatformSafeTextList(report?.limitations, 8) : [];

  let body: JSX.Element | null = null;
  if (error != null) {
    body = <ErrorState error={error} title={errorTitle} retryLabel={retryLabel} onRetry={onRetry} classNamespace={namespace} />;
  } else if (isLoading) {
    body = <LoadingState label={loadingLabel} classNamespace={namespace} />;
  } else if (!hasReport) {
    body = (
      <EmptyState
        title={emptyTitle ?? "No compliance report"}
        message={emptyMessage ?? "No compliance report is available."}
        classNamespace={namespace}
      />
    );
  } else {
    const sections = REPORT_SECTIONS.map((section) => renderSection(namespace, section, report)).filter(
      (section): section is JSX.Element => section !== null,
    );
    body = (
      <>
        <dl className={openPlatformClassName(namespace, REPORT_BLOCK, "metadata")}>
          {contractVersion === undefined ? null : (
            <>
              <dt>Contract version</dt>
              <dd data-report-metric="contractVersion">{contractVersion}</dd>
            </>
          )}
          <dt>Generated</dt>
          <dd data-report-metric="generatedAt">
            {generatedAt.dateTime === "" ? "—" : <time dateTime={generatedAt.dateTime}>{generatedAt.label}</time>}
          </dd>
          <dt>Period</dt>
          <dd data-report-metric="period">
            {periodFrom === undefined && periodTo === undefined ? "—" : `${periodFrom ?? "—"} → ${periodTo ?? "—"}`}
          </dd>
          <dt>Redaction</dt>
          <dd data-report-metric="redaction" data-redaction-applies={redactionApplies ? "true" : "false"}>
            {redactionApplies ? `Redacted values shown as ${redactionPlaceholder}` : "No redaction declared"}
          </dd>
        </dl>
        {sections.length === 0 && !redactionApplies ? (
          <EmptyState
            title={emptyTitle ?? "No compliance report details"}
            message={emptyMessage ?? "This report contains no countable sections."}
            classNamespace={namespace}
          />
        ) : null}
        {sections}
        {gaps.length > 0 && (
          <section className={openPlatformClassName(namespace, REPORT_BLOCK, "gaps")} aria-label="Report gaps">
            <h3 className={openPlatformClassName(namespace, REPORT_BLOCK, "subheading")}>Gaps</h3>
            <ul className={openPlatformClassName(namespace, REPORT_BLOCK, "gap-list")}>
              {gaps.map((gap) => (
                <li key={gap.code} className={openPlatformClassName(namespace, REPORT_BLOCK, "gap")} data-gap-code={gap.code}>
                  <span className={openPlatformClassName(namespace, REPORT_BLOCK, "gap-code")}>{gap.code}</span>
                  <span className={openPlatformClassName(namespace, REPORT_BLOCK, "gap-count")}>{gap.count}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
        {limitations.length > 0 && (
          <section className={openPlatformClassName(namespace, REPORT_BLOCK, "limitations")} aria-label="Report limitations">
            <h3 className={openPlatformClassName(namespace, REPORT_BLOCK, "subheading")}>Limitations</h3>
            <ul className={openPlatformClassName(namespace, REPORT_BLOCK, "limitation-list")}>
              {limitations.map((limitation) => (
                <li key={limitation} className={openPlatformClassName(namespace, REPORT_BLOCK, "limitation")}>
                  {limitation}
                </li>
              ))}
            </ul>
          </section>
        )}
      </>
    );
  }

  return (
    <section
      className={openPlatformClassNames(openPlatformClassName(namespace, REPORT_BLOCK), className)}
      aria-labelledby={headingId}
      aria-busy={isLoading || undefined}
      data-open-panel="compliance-report"
      data-open-platform-resource="compliance-report"
    >
      <header className={openPlatformClassName(namespace, REPORT_BLOCK, "header")}>
        <div className={openPlatformClassName(namespace, REPORT_BLOCK, "heading-group")}>
          <h2 id={headingId} className={openPlatformClassName(namespace, REPORT_BLOCK, "heading")}>
            {panelTitle}
          </h2>
          {panelCaption !== undefined && panelCaption !== null && (
            <p className={openPlatformClassName(namespace, REPORT_BLOCK, "caption")}>{panelCaption}</p>
          )}
        </div>
        {actions !== undefined && actions !== null && (
          <div className={openPlatformClassName(namespace, REPORT_BLOCK, "actions")}>{actions}</div>
        )}
      </header>
      {body}
    </section>
  );
}

export const OpenPlatformComplianceReportPanel = ComplianceReportPanel;
export const ComplianceReportSummary = ComplianceReportPanel;

function renderSection(
  namespace: string,
  section: ComplianceReportSection,
  report: OpenPlatformComplianceReport,
): JSX.Element | null {
  const source = sectionSource(report, section.source);
  const breakdowns = section.breakdowns
    .map((breakdownKey) => ({ breakdownKey, value: getOpenPlatformSafeCountBreakdown(recordValue(source, breakdownKey)) }))
    .filter((entry): entry is { breakdownKey: string; value: OpenPlatformComplianceCountBreakdownSummary } =>
      entry.value !== undefined);
  const metrics = section.metrics
    .map(([label, key]) => {
      const value = getOpenPlatformComplianceCount(recordValue(source, key));
      return value === undefined ? null : (
        <div key={key} className={openPlatformClassName(namespace, REPORT_BLOCK, "metric")}>
          <dt>{label}</dt>
          <dd data-report-metric={key}>{value}</dd>
        </div>
      );
    })
    .filter((metric): metric is JSX.Element => metric !== null);
  if (breakdowns.length === 0 && metrics.length === 0) return null;
  return (
    <section
      key={section.key}
      className={openPlatformClassName(namespace, REPORT_BLOCK, "section")}
      data-report-section={section.key}
      aria-label={section.label}
    >
      <h3 className={openPlatformClassName(namespace, REPORT_BLOCK, "subheading")}>{section.label}</h3>
      <dl className={openPlatformClassName(namespace, REPORT_BLOCK, "metrics")}>
        {breakdowns.map(({ breakdownKey, value }) => (
          <div key={`${section.key}-${breakdownKey}-total`} className={openPlatformClassName(namespace, REPORT_BLOCK, "metric")}>
            <dt>{breakdownLabel(breakdownKey)}</dt>
            <dd data-report-total={breakdownKey}>{value.total}</dd>
          </div>
        ))}
        {metrics}
        {breakdowns.flatMap(({ breakdownKey, value }) =>
          value.entries.map((entry) => (
            <div
              key={`${section.key}-${breakdownKey}-${entry.label}`}
              className={openPlatformClassName(namespace, REPORT_BLOCK, "metric")}
            >
              <dt>{breakdownLabel(breakdownKey)} · {entry.label}</dt>
              <dd data-report-count={`${breakdownKey}.${entry.label}`}>{entry.count}</dd>
            </div>
          )),
        )}
      </dl>
    </section>
  );
}

function breakdownLabel(value: string): string {
  const normalized = getOpenPlatformStatusText(value, "Unknown");
  return normalized.length === 0 ? "Unknown" : `${normalized.charAt(0).toUpperCase()}${normalized.slice(1)}`;
}

function getOpenPlatformSafeGaps(
  report: OpenPlatformComplianceReport,
): readonly { readonly code: string; readonly count: number }[] {
  if (!Array.isArray(report.gaps)) return [];
  const output: { code: string; count: number }[] = [];
  for (const gap of report.gaps) {
    if (output.length >= 12) break;
    if (gap === null || typeof gap !== "object") continue;
    const count = getOpenPlatformComplianceCount(gap.count) ?? 0;
    const code = getOpenPlatformStatusText(gap.code, "unknownGap");
    output.push({ code, count });
  }
  return output;
}

function sectionSource(report: OpenPlatformComplianceReport, key: string): unknown {
  return key === "dataCatalog"
    ? report.dataCatalog
    : key === "consent"
      ? report.consent
      : key === "privacyRequests"
        ? report.privacyRequests
        : key === "retention"
          ? report.retention
          : key === "crossBorder"
            ? report.crossBorder
            : report.vendors;
}

function recordValue(source: unknown, key: string): unknown {
  return typeof source === "object" && source !== null ? (source as Record<string, unknown>)[key] : undefined;
}
