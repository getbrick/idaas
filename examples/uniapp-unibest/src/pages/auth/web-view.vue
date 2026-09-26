<script setup lang="ts">
import { ref } from "vue";
import { onLoad } from "@dcloudio/uni-app";
import { assertWebViewMessageOrigin, parseWebViewCallback } from "../../auth/callback";
import { assertAuthorizationUrl } from "../../auth/handoff";
import { useAuthStore } from "../../stores/auth";
import { clientConfig, getWebviewBridgeOrigin, getWebviewRedirectUri } from "../../config";
import { getUniRuntime } from "../../types/runtime";

const auth = useAuthStore();
const url = ref("");
const bridgeOrigin = ref("");
const handling = ref(false);

onLoad((query) => {
  const value = query?.url;
  if (typeof value !== "string" || value.length === 0) {
    closeWebView();
    return;
  }
  try {
    const authorizationUrl = value.startsWith("https://") ? value : decodeURIComponent(value);
    assertAuthorizationUrl(authorizationUrl, getWebviewRedirectUri(clientConfig));
    bridgeOrigin.value = getWebviewBridgeOrigin(clientConfig);
    url.value = authorizationUrl;
  } catch {
    closeWebView();
  }
});

function handleMessage(event: { origin?: unknown; detail?: { data?: unknown; origin?: unknown } }): void {
  if (handling.value) return;
  const origin = event.origin ?? event.detail?.origin;
  try {
    assertWebViewMessageOrigin(origin, bridgeOrigin.value);
  } catch {
    return;
  }
  handling.value = true;
  void finish(event.detail?.data, origin);
}

async function finish(data: unknown, origin: unknown): Promise<void> {
  try {
    const callback = parseWebViewCallback(data, {
      expectedOrigin: bridgeOrigin.value,
      sourceOrigin: typeof origin === "string" ? origin : undefined,
      requireOrigin: true,
      requireState: true,
    });
    if ("error" in callback) {
      await auth.completeOidcCallback({
        state: callback.state,
        flowId: callback.flowId,
        nonce: callback.nonce,
        origin: bridgeOrigin.value,
        error: "access_denied",
      });
    } else {
      await auth.completeOidcCallback({ ...callback, origin: bridgeOrigin.value });
    }
  } catch {
    await Promise.resolve();
  } finally {
    closeWebView();
  }
}

function closeWebView(): void {
  const runtime = getUniRuntime();
  runtime.navigateBack({
    delta: 1,
    success: () => undefined,
    fail: () => runtime.redirectTo({ url: "/pages/index/index" }),
  });
}
</script>

<template>
  <web-view v-if="url" :src="url" @message="handleMessage" />
</template>
