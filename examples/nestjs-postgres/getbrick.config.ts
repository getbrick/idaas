import { defineIdaasConfig } from "@getbrick/idaas-core";

export const idaas = defineIdaasConfig({
  appName: "Getbrick Example",
  session: { expiresInDays: 7, storeInDatabase: true },
  password: { minLength: 8 },
  features: { twoFactor: true },
  rbac: {
    roles: {
      member: { extends: ["user"], permissions: ["project:read:own"] },
      owner: { extends: ["member"], permissions: ["project:write"] },
    },
  },
});
