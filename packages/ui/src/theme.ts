export const DEFAULT_THEME: ThemeTokens = {
  primary: "#4f46e5",
  surface: "#ffffff",
  surfaceMuted: "#f8fafc",
  text: "#0f172a",
  textMuted: "#64748b",
  border: "#e2e8f0",
  danger: "#dc2626",
  radius: "10px",
  fontFamily: "system-ui, -apple-system, 'Segoe UI', sans-serif",
};

export interface ThemeTokens {
  primary?: string;
  surface?: string;
  surfaceMuted?: string;
  text?: string;
  textMuted?: string;
  border?: string;
  danger?: string;
  radius?: string;
  fontFamily?: string;
}

export function themeToCssVars(theme?: ThemeTokens): Record<string, string> {
  const merged: Record<string, string> = { ...DEFAULT_THEME, ...(theme as Record<string, string> | undefined) };
  return {
    "--gb-primary": merged.primary ?? DEFAULT_THEME.primary,
    "--gb-surface": merged.surface ?? DEFAULT_THEME.surface,
    "--gb-surface-muted": merged.surfaceMuted ?? DEFAULT_THEME.surfaceMuted,
    "--gb-text": merged.text ?? DEFAULT_THEME.text,
    "--gb-text-muted": merged.textMuted ?? DEFAULT_THEME.textMuted,
    "--gb-border": merged.border ?? DEFAULT_THEME.border,
    "--gb-danger": merged.danger ?? DEFAULT_THEME.danger,
    "--gb-radius": merged.radius ?? DEFAULT_THEME.radius,
    "--gb-font": merged.fontFamily ?? DEFAULT_THEME.fontFamily,
  };
}
