import { AuthError } from "./errors";
import { getUniRuntime, type UniLoginOptions, type UniRuntime } from "../types/runtime";

export type ClientPlatform = "h5" | "app" | "mp-weixin";

export function getClientPlatform(): ClientPlatform | "unknown" {
  // #ifdef MP-WEIXIN
  return "mp-weixin";
  // #endif
  // #ifdef H5
  return "h5";
  // #endif
  // #ifdef APP-PLUS
  return "app";
  // #endif
  return "unknown";
}

export function requestWechatMiniProgramCode(runtime: UniRuntime = getUniRuntime()): Promise<string> {
  // #ifdef MP-WEIXIN
  return new Promise<string>((resolve, reject) => {
    const options: UniLoginOptions = {
      provider: "weixin",
      success: (result) => {
        const code = typeof result.code === "string" ? result.code.trim() : "";
        if (code.length === 0 || code.length > 512 || /[\u0000-\u001f\u007f\s]/u.test(code)) {
          reject(new AuthError("wechat_login_failed", "WeChat login code is invalid"));
          return;
        }
        resolve(code);
      },
      fail: () => reject(new AuthError("wechat_login_failed", "WeChat login failed")),
    };
    try {
      runtime.login(options);
    } catch {
      reject(new AuthError("wechat_login_failed", "WeChat login failed"));
    }
  });
  // #endif
  return Promise.reject(new AuthError("unsupported_platform", "WeChat login is only available in mp-weixin"));
}
