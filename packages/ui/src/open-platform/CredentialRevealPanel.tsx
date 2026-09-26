import { useEffect, useId, useRef, useState } from "react";
import {
  openPlatformClassName,
  openPlatformClassNames,
  resolveOpenPlatformClassNamespace,
  type OpenPlatformClassNamespaceProps,
} from "./theme.js";
import { getOpenPlatformText } from "./utils.js";

export const DEFAULT_CREDENTIAL_AUTO_HIDE_DELAY_MS = 30_000;

const MINIMUM_AUTO_HIDE_DELAY_MS = 1_000;
const COPY_FEEDBACK_DELAY_MS = 2_000;

export interface CredentialRevealPanelProps<TValue = string> extends OpenPlatformClassNamespaceProps {
  label: string;
  value?: TValue;
  loadValue?: () => TValue | Promise<TValue>;
  revealLabel?: string;
  hideLabel?: string;
  copyLabel?: string;
  copiedLabel?: string;
  loadingLabel?: string;
  errorMessage?: string;
  maskedValue?: string;
  disabled?: boolean;
  canCopy?: boolean;
  autoHideDelayMs?: number | false;
  formatValue?: (value: TValue) => string;
  onReveal?: () => void;
  onHide?: () => void;
  onCopy?: (value: TValue, text: string) => void | Promise<void>;
}

export function CredentialRevealPanel<TValue = string>({
  label,
  value,
  loadValue,
  revealLabel,
  hideLabel,
  copyLabel,
  copiedLabel,
  loadingLabel,
  errorMessage,
  maskedValue,
  disabled = false,
  canCopy = true,
  autoHideDelayMs = DEFAULT_CREDENTIAL_AUTO_HIDE_DELAY_MS,
  formatValue,
  onReveal,
  onHide,
  onCopy,
  className,
  ...namespaceProps
}: CredentialRevealPanelProps<TValue>) {
  const namespace = resolveOpenPlatformClassNamespace(namespaceProps);
  const labelId = useId();
  const valueId = useId();
  const [loadedValue, setLoadedValue] = useState<TValue>();
  const [isRevealed, setIsRevealed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [isCopied, setIsCopied] = useState(false);
  const requestId = useRef(0);
  const mounted = useRef(true);
  const autoHideTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const accessibleLabel = getOpenPlatformText(label, 256) ?? "Credential";
  const visibleRevealLabel = getOpenPlatformText(revealLabel, 128) ?? "Reveal credential";
  const visibleHideLabel = getOpenPlatformText(hideLabel, 128) ?? "Hide credential";
  const visibleCopyLabel = getOpenPlatformText(copyLabel, 128) ?? "Copy credential";
  const visibleCopiedLabel = getOpenPlatformText(copiedLabel, 128) ?? "Copied";
  const visibleLoadingLabel = getOpenPlatformText(loadingLabel, 128) ?? "Revealing credential";
  const visibleErrorMessage = getOpenPlatformText(errorMessage, 256) ?? "Unable to reveal credential.";
  const hiddenValue = getOpenPlatformText(maskedValue, 128) ?? "••••••••••••";
  const formatter = formatValue ?? ((credential: TValue) => String(credential));
  const hasProvidedValue = value !== undefined && value !== null;
  const hasCredential = hasProvidedValue || loadValue !== undefined;
  const currentValue = loadValue === undefined ? value : loadedValue;
  const canDisplayValue = isRevealed && currentValue !== undefined && currentValue !== null;
  const autoHideDelay = normalizeAutoHideDelay(autoHideDelayMs);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      requestId.current += 1;
      if (autoHideTimer.current) clearTimeout(autoHideTimer.current);
      if (copyTimer.current) clearTimeout(copyTimer.current);
    };
  }, []);

  function clearCopiedState() {
    setIsCopied(false);
    if (copyTimer.current) clearTimeout(copyTimer.current);
  }

  function clearAutoHideTimer() {
    if (autoHideTimer.current) clearTimeout(autoHideTimer.current);
  }

  function scheduleAutoHide() {
    clearAutoHideTimer();
    if (autoHideDelay === false) return;
    autoHideTimer.current = setTimeout(() => hideCredential(true), autoHideDelay);
  }

  function hideCredential(clearCopied: boolean) {
    requestId.current += 1;
    clearAutoHideTimer();
    setIsRevealed(false);
    setLoadedValue(undefined);
    setIsLoading(false);
    setHasError(false);
    if (clearCopied) clearCopiedState();
    onHide?.();
  }

  async function handleReveal() {
    if (disabled || isLoading) return;
    const activeRequest = requestId.current + 1;
    requestId.current = activeRequest;
    clearAutoHideTimer();
    clearCopiedState();
    setHasError(false);
    onReveal?.();
    if (loadValue === undefined) {
      if (!hasProvidedValue) {
        setHasError(true);
        return;
      }
      setIsRevealed(true);
      scheduleAutoHide();
      return;
    }
    setIsLoading(true);
    try {
      const result = await loadValue();
      if (!mounted.current || requestId.current !== activeRequest) return;
      if (result === undefined || result === null) {
        setHasError(true);
        return;
      }
      setLoadedValue(result);
      setIsRevealed(true);
      scheduleAutoHide();
    } catch {
      if (mounted.current && requestId.current === activeRequest) setHasError(true);
    } finally {
      if (mounted.current && requestId.current === activeRequest) setIsLoading(false);
    }
  }

  async function handleCopy() {
    if (!canDisplayValue || currentValue === undefined || currentValue === null) return;
    const activeRequest = requestId.current;
    const credential = currentValue;
    const text = formatter(credential);
    setHasError(false);
    try {
      if (onCopy) await onCopy(credential, text);
      else {
        if (typeof navigator === "undefined" || !navigator.clipboard) throw new Error("Clipboard unavailable");
        await navigator.clipboard.writeText(text);
      }
      if (!mounted.current || requestId.current !== activeRequest) return;
      setIsCopied(true);
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setIsCopied(false), COPY_FEEDBACK_DELAY_MS);
      hideCredential(false);
    } catch {
      if (mounted.current) setHasError(true);
    }
  }

  const displayedValue = canDisplayValue ? formatter(currentValue as TValue) : hiddenValue;

  return (
    <section
      className={openPlatformClassNames(openPlatformClassName(namespace, "credential-reveal-panel"), className)}
      data-credential-revealed={isRevealed ? "true" : "false"}
      role="group"
      aria-labelledby={labelId}
      aria-busy={isLoading || undefined}
    >
      <div className={openPlatformClassName(namespace, "credential-reveal-panel", "header")}>
        <span id={labelId} className={openPlatformClassName(namespace, "credential-reveal-panel", "label")}>
          {accessibleLabel}
        </span>
        <span className={openPlatformClassName(namespace, "credential-reveal-panel", "state")} aria-live="polite">
          {canDisplayValue ? "Credential revealed" : "Credential hidden"}
        </span>
      </div>
      <div id={valueId} className={openPlatformClassName(namespace, "credential-reveal-panel", "value")}>
        {canDisplayValue ? <code>{displayedValue}</code> : <span aria-label="Credential hidden">{displayedValue}</span>}
      </div>
      <div
        className={openPlatformClassName(namespace, "credential-reveal-panel", "controls")}
        role="group"
        aria-label={`${accessibleLabel} controls`}
      >
        {canDisplayValue ? (
          <button
            className={openPlatformClassName(namespace, "credential-reveal-panel", "hide-button")}
            type="button"
            aria-controls={valueId}
            aria-expanded="true"
            onClick={() => hideCredential(true)}
          >
            {visibleHideLabel}
          </button>
        ) : (
          <button
            className={openPlatformClassName(namespace, "credential-reveal-panel", "reveal-button")}
            type="button"
            aria-controls={valueId}
            aria-expanded="false"
            disabled={disabled || isLoading || !hasCredential}
            onClick={handleReveal}
          >
            {isLoading ? visibleLoadingLabel : visibleRevealLabel}
          </button>
        )}
        {canDisplayValue && canCopy && (
          <button
            className={openPlatformClassName(namespace, "credential-reveal-panel", "copy-button")}
            type="button"
            disabled={isLoading}
            onClick={handleCopy}
          >
            {visibleCopyLabel}
          </button>
        )}
      </div>
      {isCopied && (
        <span className={openPlatformClassName(namespace, "credential-reveal-panel", "copy-status")} role="status">
          {visibleCopiedLabel}
        </span>
      )}
      {hasError && (
        <span className={openPlatformClassName(namespace, "credential-reveal-panel", "error")} role="alert">
          {visibleErrorMessage}
        </span>
      )}
    </section>
  );
}

function normalizeAutoHideDelay(value: number | false): number | false {
  if (value === false) return false;
  if (!Number.isFinite(value) || value <= 0) return DEFAULT_CREDENTIAL_AUTO_HIDE_DELAY_MS;
  return Math.max(MINIMUM_AUTO_HIDE_DELAY_MS, Math.floor(value));
}
