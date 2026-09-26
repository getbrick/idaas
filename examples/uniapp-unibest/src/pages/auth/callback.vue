<script setup lang="ts">
import { ref } from "vue";
import { onLoad } from "@dcloudio/uni-app";
import { useAuthStore } from "../../stores/auth";
import { getUniRuntime } from "../../types/runtime";

const auth = useAuthStore();
const status = ref("正在处理登录回调");

onLoad((query) => {
  void handleCallback(query as Record<string, unknown>);
});

async function handleCallback(query: Record<string, unknown>): Promise<void> {
  await auth.completeOidcCallback(query);
  if (auth.error !== null) {
    status.value = auth.errorMessage ?? "登录回调失败";
    return;
  }
  status.value = "登录成功";
  const runtime = getUniRuntime();
  runtime.redirectTo({
    url: "/pages/index/index",
    success: () => undefined,
    fail: () => runtime.navigateBack({ delta: 1 }),
  });
}
</script>

<template>
  <view class="callback-page">
    <text>{{ status }}</text>
  </view>
</template>

<style scoped>
.callback-page {
  display: flex;
  min-height: 100vh;
  align-items: center;
  justify-content: center;
  padding: 48rpx;
  color: #6b7280;
  font-size: 28rpx;
}
</style>
