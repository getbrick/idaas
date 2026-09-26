import { computed, ref } from "vue";
import { defineStore } from "pinia";
import { getAuthClient, type AuthClient } from "../auth";
import { toAuthError, type AuthError } from "../auth/errors";
import type { OidcCallbackInput } from "../auth/callback";
import type { OpaqueSession, PublicUser } from "../auth/session";

export const useAuthStore = defineStore("auth", () => {
  const client: AuthClient = getAuthClient();
  const session = ref<OpaqueSession | null>(null);
  const cookieAuthenticated = ref(false);
  const cookieUser = ref<PublicUser | null>(null);
  const loading = ref(false);
  const error = ref<AuthError | null>(null);
  const errorMessage = computed(() => error.value === null ? null : safeMessage(error.value.code));
  const user = computed<PublicUser | null>(() => cookieUser.value ?? session.value?.user ?? null);
  const authenticated = computed(() => cookieAuthenticated.value || session.value !== null);

  async function bootstrap(): Promise<void> {
    await run(async () => {
      session.value = await client.bootstrap();
      syncClientState();
    });
  }

  async function loginWithWechat(): Promise<OpaqueSession | null> {
    return run(() => client.loginWithWechat());
  }

  async function loginWithOidc(): Promise<boolean> {
    let started = false;
    await run(async () => {
      await client.startOidcLogin();
      started = true;
    });
    return started;
  }

  async function completeOidcCallback(input: OidcCallbackInput): Promise<OpaqueSession | null> {
    return run(() => client.completeOidcCallback(input));
  }

  async function refresh(): Promise<OpaqueSession | null> {
    return run(() => client.refresh());
  }

  async function me(): Promise<PublicUser | null> {
    return run(() => client.me());
  }

  async function logout(): Promise<void> {
    await run(async () => {
      await client.logout();
      session.value = null;
      cookieAuthenticated.value = false;
      cookieUser.value = null;
    });
  }

  async function run<T>(operation: () => Promise<T>): Promise<T | null> {
    loading.value = true;
    error.value = null;
    try {
      const result = await operation();
      syncClientState();
      return result;
    } catch (cause) {
      error.value = toAuthError(cause, "invalid_auth_response", "Authentication failed");
      syncClientState();
      return null;
    } finally {
      loading.value = false;
    }
  }

  function syncClientState(): void {
    session.value = client.getSession();
    cookieAuthenticated.value = client.isCookieAuthenticated();
    cookieUser.value = client.getUser();
  }

  return {
    session,
    cookieAuthenticated,
    cookieUser,
    user,
    authenticated,
    loading,
    error,
    errorMessage,
    bootstrap,
    loginWithWechat,
    loginWithOidc,
    completeOidcCallback,
    refresh,
    me,
    logout,
  };
});

function safeMessage(code: string): string {
  switch (code) {
    case "session_expired":
      return "登录状态已过期";
    case "session_missing":
    case "unauthorized":
      return "登录状态不可用";
    case "session_generation_mismatch":
      return "登录状态已变化，请重试";
    case "cookie_session_unavailable":
      return "Cookie 会话暂不可用";
    case "oidc_state_mismatch":
    case "oidc_flow_mismatch":
    case "oidc_nonce_mismatch":
    case "oidc_origin_mismatch":
      return "登录状态校验失败";
    case "oidc_callback_denied":
      return "已取消授权";
    case "wechat_login_failed":
      return "微信登录失败";
    case "network_error":
      return "网络请求失败";
    default:
      return "认证请求失败";
  }
}
