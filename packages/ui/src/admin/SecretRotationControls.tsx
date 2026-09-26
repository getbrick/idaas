import type { AdminSecretRotationTarget } from "./contracts.js";
import { getAdminMetadataText, getAdminVersion } from "./listUtils.js";
import {
  adminClassName,
  adminClassNames,
  resolveAdminClassNamespace,
  type AdminClassNamespaceProps,
} from "./theme.js";

export interface AdminSecretRotationControlsProps extends AdminClassNamespaceProps {
  target: AdminSecretRotationTarget;
  block?: string;
  label?: string;
  disabled?: boolean;
  canRotate?: boolean;
  onRotate?: (target: AdminSecretRotationTarget) => void;
  onRotateSecret?: (target: AdminSecretRotationTarget) => void;
}

export function AdminSecretRotationControls({
  target,
  block = "secret-rotation",
  label,
  disabled = false,
  canRotate = true,
  onRotate,
  onRotateSecret,
  className,
  ...namespaceProps
}: AdminSecretRotationControlsProps) {
  const namespace = resolveAdminClassNamespace(namespaceProps);
  const callback = onRotateSecret ?? onRotate;
  if (!callback) return null;
  const accessibleLabel = label?.trim() || "Rotate secret";
  const id = getAdminMetadataText(target.id, 256);
  const applicationId = getAdminMetadataText(target.applicationId, 256);
  const version = getAdminVersion(target.version);
  const etag = getAdminMetadataText(target.etag);
  const safeTarget: AdminSecretRotationTarget = {
    kind: target.kind,
    id: id ?? "",
    applicationId: applicationId ?? "",
    ...(version === undefined ? {} : { version, expectedVersion: version }),
    ...(etag === undefined ? {} : { etag }),
  };
  return (
    <button
      className={adminClassNames(adminClassName(namespace, block, "control"), className)}
      type="button"
      disabled={disabled || !canRotate || !id || !applicationId}
      aria-label={accessibleLabel}
      data-secret-rotation="true"
      data-rotation-kind={target.kind}
      onClick={() => callback(safeTarget)}
    >
      {accessibleLabel}
    </button>
  );
}

export const SecretRotationControls = AdminSecretRotationControls;
export const AdminSecretRotationButton = AdminSecretRotationControls;
