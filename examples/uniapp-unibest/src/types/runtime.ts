export type UniRequestMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

export interface UniRequestError {
  errMsg?: string;
  errCode?: number;
}

export interface UniResponse {
  statusCode: number;
  data: unknown;
}

export interface UniRequestOptions {
  url: string;
  method?: UniRequestMethod;
  data?: unknown;
  header?: Record<string, string>;
  withCredentials?: boolean;
  timeout?: number;
  success?: (response: UniResponse) => void;
  fail?: (error: UniRequestError) => void;
  complete?: () => void;
}

export interface UniLoginSuccess {
  code?: string;
  [key: string]: unknown;
}

export interface UniLoginOptions {
  provider?: string;
  success?: (result: UniLoginSuccess) => void;
  fail?: (error: UniRequestError) => void;
  complete?: () => void;
}

export interface UniNavigationOptions {
  url: string;
  success?: () => void;
  fail?: (error: UniRequestError) => void;
  complete?: () => void;
}

export interface UniToastOptions {
  title: string;
  icon?: "none" | "success" | "error";
  duration?: number;
}

export interface UniRuntime {
  request(options: UniRequestOptions): unknown;
  login(options: UniLoginOptions): unknown;
  navigateTo(options: UniNavigationOptions): unknown;
  redirectTo(options: UniNavigationOptions): unknown;
  navigateBack(options?: { delta?: number; success?: () => void; fail?: (error: UniRequestError) => void }): unknown;
  getStorageSync(key: string): unknown;
  setStorageSync(key: string, value: unknown): void;
  removeStorageSync(key: string): void;
  showToast(options: UniToastOptions): unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function getUniRuntime(): UniRuntime {
  const value = (globalThis as { uni?: unknown }).uni;
  if (!isRecord(value)) {
    throw new Error("UniApp runtime is unavailable");
  }
  const runtime = value as Partial<UniRuntime>;
  if (
    typeof runtime.request !== "function" ||
    typeof runtime.login !== "function" ||
    typeof runtime.navigateTo !== "function" ||
    typeof runtime.redirectTo !== "function" ||
    typeof runtime.navigateBack !== "function" ||
    typeof runtime.getStorageSync !== "function" ||
    typeof runtime.setStorageSync !== "function" ||
    typeof runtime.removeStorageSync !== "function" ||
    typeof runtime.showToast !== "function"
  ) {
    throw new Error("UniApp runtime is incomplete");
  }
  return runtime as UniRuntime;
}

export function createMemoryStorage(): KeyValueStorage {
  const values = new Map<string, string>();
  return {
    get(key) {
      return values.get(key);
    },
    set(key, value) {
      values.set(key, value);
    },
    remove(key) {
      values.delete(key);
    },
  };
}

export interface KeyValueStorage {
  get(key: string): string | undefined;
  set(key: string, value: string): void;
  remove(key: string): void;
}

export function createUniStorage(): KeyValueStorage {
  const runtime = getUniRuntime();
  return {
    get(key) {
      const value = runtime.getStorageSync(key);
      return typeof value === "string" ? value : undefined;
    },
    set(key, value) {
      runtime.setStorageSync(key, value);
    },
    remove(key) {
      runtime.removeStorageSync(key);
    },
  };
}
