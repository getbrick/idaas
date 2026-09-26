<script setup lang="ts">
import { computed, onMounted } from "vue";
import { useAuthStore } from "../../stores/auth";

const auth = useAuthStore();
const userName = computed(() => auth.user?.name ?? "未登录");

onMounted(() => {
  void auth.bootstrap();
});

async function loginWithWechat(): Promise<void> {
  await auth.loginWithWechat();
}

async function loginWithOidc(): Promise<void> {
  await auth.loginWithOidc();
}

async function refresh(): Promise<void> {
  await auth.refresh();
}

async function logout(): Promise<void> {
  await auth.logout();
}
</script>

<template>
  <view class="page">
    <view class="hero">
      <text class="eyebrow">GETBRICK CLIENT</text>
      <text class="title">跨端身份认证模板</text>
      <text class="subtitle">mp-weixin、H5 与 App 共用 opaque client session</text>
    </view>

    <view class="card">
      <view class="row">
        <text class="label">当前用户</text>
        <text class="value">{{ userName }}</text>
      </view>
      <view v-if="auth.authenticated" class="row">
        <text class="label">会话有效期</text>
        <text class="value">{{ auth.session?.expiresAt }}</text>
      </view>
      <text v-if="auth.errorMessage" class="error">{{ auth.errorMessage }}</text>
    </view>

    <view v-if="!auth.authenticated" class="actions">
      <!-- #ifdef MP-WEIXIN -->
      <button class="primary" :loading="auth.loading" @click="loginWithWechat">微信登录</button>
      <!-- #endif -->
      <!-- #ifdef H5 -->
      <button class="primary" :loading="auth.loading" @click="loginWithOidc">OIDC 登录</button>
      <!-- #endif -->
      <!-- #ifdef APP-PLUS -->
      <button class="primary" :loading="auth.loading" @click="loginWithOidc">OIDC 登录</button>
      <!-- #endif -->
    </view>

    <view v-else class="actions">
      <button class="secondary" :loading="auth.loading" @click="refresh">刷新会话</button>
      <button class="danger" :loading="auth.loading" @click="logout">退出登录</button>
    </view>
  </view>
</template>

<style scoped>
.page {
  min-height: 100vh;
  padding: 48rpx;
  box-sizing: border-box;
}

.hero {
  padding: 48rpx 8rpx;
}

.eyebrow {
  display: block;
  color: #2563eb;
  font-size: 22rpx;
  letter-spacing: 4rpx;
}

.title {
  display: block;
  margin-top: 20rpx;
  font-size: 48rpx;
  font-weight: 700;
}

.subtitle {
  display: block;
  margin-top: 16rpx;
  color: #6b7280;
  font-size: 26rpx;
  line-height: 1.6;
}

.card {
  padding: 32rpx;
  border-radius: 24rpx;
  background: #ffffff;
  box-shadow: 0 12rpx 40rpx rgba(15, 23, 42, 0.06);
}

.row {
  display: flex;
  justify-content: space-between;
  gap: 24rpx;
  padding: 18rpx 0;
  border-bottom: 1px solid #e5e7eb;
}

.row:last-child {
  border-bottom: 0;
}

.label {
  color: #6b7280;
  font-size: 26rpx;
}

.value {
  max-width: 60%;
  color: #111827;
  font-size: 26rpx;
  text-align: right;
  word-break: break-all;
}

.error {
  display: block;
  margin-top: 20rpx;
  color: #dc2626;
  font-size: 24rpx;
}

.actions {
  display: flex;
  flex-direction: column;
  gap: 20rpx;
  margin-top: 32rpx;
}

button {
  border: 0;
  border-radius: 16rpx;
  font-size: 28rpx;
}

.primary {
  background: #2563eb;
  color: #ffffff;
}

.secondary {
  background: #e5e7eb;
  color: #1f2937;
}

.danger {
  background: #fee2e2;
  color: #b91c1c;
}
</style>
