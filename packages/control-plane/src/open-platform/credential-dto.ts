import type {
  CredentialDto,
  CredentialRecord,
} from "./types.js";

export function toCredentialDto(record: CredentialRecord): CredentialDto {
  return {
    id: record.id,
    tenantId: record.tenantId,
    kind: "credential",
    applicationId: record.applicationId,
    ...(record.environmentId === undefined
      ? {}
      : { environmentId: record.environmentId }),
    name: record.name,
    status: record.status,
    scopes: [...record.scopes],
    ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
    ...(record.rotatedAt === undefined ? {} : { rotatedAt: record.rotatedAt }),
    ...(record.revokedAt === undefined ? {} : { revokedAt: record.revokedAt }),
    ...(record.replacedByCredentialId === undefined
      ? {}
      : { replacedByCredentialId: record.replacedByCredentialId }),
    ...(record.previousCredentialId === undefined
      ? {}
      : { previousCredentialId: record.previousCredentialId }),
    version: record.version,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
}

export function cloneCredentialDto(dto: CredentialDto): CredentialDto {
  return {
    id: dto.id,
    tenantId: dto.tenantId,
    kind: "credential",
    applicationId: dto.applicationId,
    ...(dto.environmentId === undefined
      ? {}
      : { environmentId: dto.environmentId }),
    name: dto.name,
    status: dto.status,
    scopes: [...dto.scopes],
    ...(dto.expiresAt === undefined ? {} : { expiresAt: dto.expiresAt }),
    ...(dto.rotatedAt === undefined ? {} : { rotatedAt: dto.rotatedAt }),
    ...(dto.revokedAt === undefined ? {} : { revokedAt: dto.revokedAt }),
    ...(dto.replacedByCredentialId === undefined
      ? {}
      : { replacedByCredentialId: dto.replacedByCredentialId }),
    ...(dto.previousCredentialId === undefined
      ? {}
      : { previousCredentialId: dto.previousCredentialId }),
    version: dto.version,
    createdAt: dto.createdAt,
    updatedAt: dto.updatedAt,
  };
}

export function toCredentialDtoList(
  records: readonly CredentialRecord[],
): CredentialDto[] {
  return records.map((record) => toCredentialDto(record));
}
