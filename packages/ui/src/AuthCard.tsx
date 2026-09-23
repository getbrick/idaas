import type { CSSProperties, ReactNode } from "react";
import type { ThemeTokens } from "./theme.js";
import { themeToCssVars } from "./theme.js";

export interface AuthCardProps {
  title: string;
  subtitle?: string;
  logo?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  theme?: ThemeTokens;
  style?: CSSProperties;
}

export function AuthCard({ title, subtitle, logo, footer, children, theme, style }: AuthCardProps) {
  return (
    <div className="gb-auth-card" style={{ ...themeToCssVars(theme), ...style } as CSSProperties}>
      {(logo || title) && (
        <div className="gb-auth-card__head">
          {logo && <div className="gb-auth-card__logo">{logo}</div>}
          <h1 className="gb-auth-card__title">{title}</h1>
          {subtitle && <p className="gb-auth-card__subtitle">{subtitle}</p>}
        </div>
      )}
      {children}
      {footer && <div className="gb-auth-card__footer">{footer}</div>}
    </div>
  );
}
