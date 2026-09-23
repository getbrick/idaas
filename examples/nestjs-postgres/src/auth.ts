import { Pool } from "pg";
import { createIdaas } from "@getbrick/idaas-core";
import { idaas } from "../getbrick.config.js";

const connectionString =
  process.env.DATABASE_URL ??
  "postgres://postgres:gbtest@localhost:54329/getbrick";

export const pool = new Pool({ connectionString });

export const auth = createIdaas({
  config: idaas,
  database: pool,
});
