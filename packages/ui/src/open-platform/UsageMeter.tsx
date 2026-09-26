import { useId, type ReactNode } from "react";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  type OpenPlatformClassNamespaceProps,
} from "./theme.js";
import { getOpenPlatformText } from "./utils.js";

export type UsageMeterLevel = "normal" | "warning" | "limit";

export interface UsageMeterProps extends OpenPlatformClassNamespaceProps {
  label: string;
  value: number;
  min?: number;
  max?: number;
  low?: number;
  high?: number;
  optimum?: number;
  description?: ReactNode;
  valueText?: string;
  formatValue?: (value: number, max: number) => string;
  showValue?: boolean;
}

export function UsageMeter({
  label,
  value,
  min: minProp,
  max: maxProp,
  low: lowProp,
  high: highProp,
  optimum: optimumProp,
  description,
  valueText,
  formatValue,
  showValue = true,
  className,
  ...namespaceProps
}: UsageMeterProps) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const labelId = useId();
  const descriptionId = useId();
  const min = finiteNumber(minProp, 0);
  const requestedMax = finiteNumber(maxProp, 100);
  const max = requestedMax > min ? requestedMax : min + Math.max(1, Math.abs(min));
  const currentValue = clamp(finiteNumber(value, min), min, max);
  const low = clamp(finiteNumber(lowProp, min), min, max);
  const requestedHigh = clamp(finiteNumber(highProp, max), min, max);
  const high = Math.max(low, requestedHigh);
  const optimum = clamp(finiteNumber(optimumProp, min), min, max);
  const accessibleLabel = getOpenPlatformText(label, 256) ?? "Usage";
  const formatter = formatValue ?? ((current: number, maximum: number) => `${current} of ${maximum}`);
  const formattedValue = getOpenPlatformText(valueText, 512) ?? formatter(currentValue, max);
  const level: UsageMeterLevel = currentValue >= max ? "limit" : currentValue >= high && high < max ? "warning" : "normal";

  return (
    <div
      className={openPlatformClassNames(openPlatformClassName(namespace, "usage-meter"), className)}
      data-usage-level={level}
      data-usage-value={currentValue}
      data-usage-max={max}
      role="meter"
      aria-labelledby={labelId}
      aria-describedby={description !== undefined && description !== null ? descriptionId : undefined}
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={currentValue}
      aria-valuetext={formattedValue}
    >
      <div className={openPlatformClassName(namespace, "usage-meter", "header")}>
        <span id={labelId} className={openPlatformClassName(namespace, "usage-meter", "label")}>
          {accessibleLabel}
        </span>
        {showValue && (
          <span className={openPlatformClassName(namespace, "usage-meter", "value")}>{formattedValue}</span>
        )}
      </div>
      {description !== undefined && description !== null && (
        <div id={descriptionId} className={openPlatformClassName(namespace, "usage-meter", "description")}>
          {description}
        </div>
      )}
      <meter
        className={openPlatformClassName(namespace, "usage-meter", "indicator")}
        min={min}
        max={max}
        low={low}
        high={high}
        optimum={optimum}
        value={currentValue}
        aria-hidden="true"
      >
        {formattedValue}
      </meter>
    </div>
  );
}

function finiteNumber(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
