import type { ReactNode } from "react";
import type {
  ApplicationClientListQuery as SharedApplicationClientListQuery,
  ApplicationClientStatus as SharedApplicationClientStatus,
  ApplicationClientSummary as SharedApplicationClientSummary,
  ApplicationEffectiveStatus as SharedApplicationEffectiveStatus,
  ApplicationExternalIdentityListQuery as SharedApplicationExternalIdentityListQuery,
  ApplicationExternalIdentitySummary as SharedApplicationExternalIdentitySummary,
  ApplicationListQuery as SharedApplicationListQuery,
  ApplicationPage as SharedApplicationPage,
  ApplicationPlatformListQuery as SharedApplicationPlatformListQuery,
  ApplicationPlatformSummary as SharedApplicationPlatformSummary,
  ApplicationPlatformType as SharedApplicationPlatformType,
  ApplicationReadiness as SharedApplicationReadiness,
  ApplicationReadinessCheck as SharedApplicationReadinessCheck,
  ApplicationReadinessDetails as SharedApplicationReadinessDetails,
  ApplicationReadinessStatus as SharedApplicationReadinessStatus,
  ApplicationSecretStatus as SharedApplicationSecretStatus,
  ApplicationStatus as SharedApplicationStatus,
  ApplicationSummary as SharedApplicationSummary,
  ApplicationTokenEndpointAuthMethod as SharedApplicationTokenEndpointAuthMethod,
  ApplicationType as SharedApplicationType,
  ApplicationVersion as SharedApplicationVersion,
  AuditEventSummary as SharedAuditEventSummary,
  ErrorEnvelope as SharedErrorEnvelope,
  ErrorResponse as SharedErrorResponse,
  RoleSummary as SharedRoleSummary,
  UserSummary as SharedUserSummary,
} from "@getbrick/idaas-contracts";
import type { AdminClassNamespaceProps } from "./theme.js";

export type AdminUserStatus = "active" | "invited" | "suspended" | "banned" | (string & {});

export type AdminUser = Partial<SharedUserSummary> & Pick<SharedUserSummary, "id"> & {
  name?: string | null;
  email?: string | null;
  status?: AdminUserStatus;
  role?: string | null;
  roles?: readonly string[];
  createdAt?: string | Date;
  lastLoginAt?: string | Date;
};

export type AdminRole = Partial<SharedRoleSummary> & Pick<SharedRoleSummary, "id"> & {
  name: string;
  code?: string | null;
  description?: string | null;
  permissions?: readonly string[];
  memberCount?: number;
};

export type AdminApplicationType = SharedApplicationType;
export type AdminApplicationStatus = SharedApplicationStatus;
export type AdminApplicationClientStatus = SharedApplicationClientStatus;
export type AdminApplicationLifecycleStatus = SharedApplicationStatus;
export type AdminApplicationPlatformType = SharedApplicationPlatformType;
export type AdminApplicationEffectiveStatus = SharedApplicationEffectiveStatus;
export type AdminApplicationReadinessStatus = SharedApplicationReadinessStatus;
export type AdminApplicationSecretStatus = SharedApplicationSecretStatus;
export type AdminApplicationVersion = SharedApplicationVersion;
export type AdminApplicationTokenEndpointAuthMethod = SharedApplicationTokenEndpointAuthMethod;
export type AdminApplicationReadinessCheck = SharedApplicationReadinessCheck;
export type AdminApplicationReadinessDetails = SharedApplicationReadinessDetails;
export type AdminApplicationReadiness = SharedApplicationReadiness;

type Presentation<T extends object, K extends keyof T> = Partial<T> & Pick<T, K>;

export type AdminApplication = Presentation<SharedApplicationSummary, "id" | "name" | "slug">;
export type AdminApplicationPlatform = Presentation<SharedApplicationPlatformSummary, "id" | "type"> & { lifecycleStatus?: SharedApplicationStatus };
export type AdminApplicationClient = Presentation<SharedApplicationClientSummary, "id" | "applicationId" | "clientId"> & { lifecycleStatus?: SharedApplicationStatus };
export type AdminApplicationExternalIdentity = Presentation<SharedApplicationExternalIdentitySummary, "id" | "applicationId" | "provider" | "subject">;
export type AdminApplicationSummary = AdminApplication;
export type AdminApplicationPlatformSummary = AdminApplicationPlatform;
export type AdminApplicationClientSummary = AdminApplicationClient;
export type AdminApplicationExternalIdentitySummary = AdminApplicationExternalIdentity;
export type AdminExternalIdentity = AdminApplicationExternalIdentity;

export type AdminApplicationPage<T> = SharedApplicationPage<T>;
export type AdminCursorPage<T> = SharedApplicationPage<T>;
export type AdminApplicationsPage<T extends AdminApplication = AdminApplication> = AdminApplicationPage<T>;
export type AdminApplicationPlatformsPage<T extends AdminApplicationPlatform = AdminApplicationPlatform> = AdminApplicationPage<T>;
export type AdminApplicationClientsPage<T extends AdminApplicationClient = AdminApplicationClient> = AdminApplicationPage<T>;
export type AdminApplicationExternalIdentitiesPage<T extends AdminApplicationExternalIdentity = AdminApplicationExternalIdentity> = AdminApplicationPage<T>;
export type AdminApplicationListQuery = SharedApplicationListQuery;
export type AdminApplicationPlatformListQuery = SharedApplicationPlatformListQuery;
export type AdminApplicationClientListQuery = SharedApplicationClientListQuery;
export type AdminApplicationExternalIdentityListQuery = SharedApplicationExternalIdentityListQuery;

export interface AdminPagination {
  cursor?: string;
  nextCursor?: string;
  previousCursor?: string;
  hasMore?: boolean;
  page?: number;
  pageSize?: number;
  total?: number;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  onCursorChange?: (cursor?: string) => void;
  onNext?: () => void;
  onPrevious?: () => void;
  onLoadMore?: () => void;
  hasNext?: boolean;
  hasPrevious?: boolean;
  onPageChange?: (page: number) => void;
}

export interface AdminSecretRotationTarget {
  kind: "application-platform" | "application-client";
  id: string;
  applicationId: string;
  version?: AdminApplicationVersion;
  expectedVersion?: AdminApplicationVersion;
  etag?: string;
}

export type AdminRotateSecretTarget = AdminSecretRotationTarget;

export interface AdminAuditActor {
  id?: string;
  name?: string | null;
  email?: string | null;
}

export type AdminAuditEvent = Pick<SharedAuditEventSummary, "event"> & Partial<Omit<SharedAuditEventSummary, "event">> & {
  id: string;
  occurredAt?: string | Date;
  detail?: unknown;
  actor?: string | AdminAuditActor | null;
};

export type AdminError = Partial<SharedErrorEnvelope> & Partial<SharedErrorResponse> & {
  message?: string;
  error?: SharedErrorEnvelope;
};

export type AdminErrorValue = AdminError | Error | string | null | undefined;

export interface AdminNavigationItem {
  id: string;
  label: string;
  href?: string;
  onSelect?: (item: AdminNavigationItem) => void;
  disabled?: boolean;
}

export interface AdminListBaseProps extends AdminClassNamespaceProps {
  title?: string;
  caption?: ReactNode;
  actions?: ReactNode;
  loading?: boolean;
  isLoading?: boolean;
  error?: AdminErrorValue;
  onRetry?: () => void;
  emptyTitle?: string;
  emptyMessage?: string;
  errorTitle?: string;
  loadingLabel?: string;
  retryLabel?: string;
}
