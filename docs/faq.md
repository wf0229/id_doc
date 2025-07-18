# 常见问题（FAQ）

---

## 校友能否访问WVPN、IDP等系统？

不能。校友访问这些系统不符合学校与供应商的采购合同要求，存在法律风险。

---

## 账号无法访问OA公文、财务、合同等系统？

OA公文系统、财务、合同等应用，对用户身份类型做了严格限定。如果统一身份认证无法进入这些系统，请联系相应主管单位：

- **OA公文系统**：[党政办公室](https://po.ustc.edu.cn/14693/list.psp)——OA系统管理员
- **财务综合信息平台、合同系统**：[财务处](https://finance.ustc.edu.cn/gzry/list.psp)——信息办公室

---

## 是否支持在同一台电脑登录不同账号？

不支持同时登录。如果需要切换账号，请先注销当前账号，关闭浏览器，再登录新账号。

---

## 什么样的密码属于弱密码？

以下类型均属于弱密码：

1. 与账号相同
2. 键盘顺序输入（如 `123456`、`qwertyui`)
3. 字母顺序型（如 `abcdabcd`、`abcabc`)
4. 手机号、出生年月日
5. 常见单词、短语（如 `password`、`admin`、`hello`)
6. 重复数字或字母（如 `666666`、`aaaaaaaa`)
7. 学号、工资号、手机号、电子邮箱

---

## 什么样的密码属于安全密码？

密码要求：

- 长度≥8位
- 至少包含以下三种类型：
  - 大写字母
  - 小写字母
  - 数字
  - 特殊符号（_、!、@、#、$、%、^、&、*、(、)、-、+、=）

---

## 如何使用修改或找回密码？

在统一认证登录页面，点击「忘记密码」，按提示操作。

---

## 什么是动态因子（TOTP）？

动态因子（TOTP）是一种基于时间的一次性密码，每30秒更新一次，用于二次验证。与短信相比，TOTP更安全可靠，也适合海外用户。

### 不同系统推荐的动态因子（TOTP）应用？

| 操作系统 / 平台     | 推荐应用                                | 备注                                  |
|---------------------|-----------------------------------------|---------------------------------------|
| **iOS / iPadOS**    | ✅ [Passwords](https://apps.apple.com/us/app/passwords/id6473799789) by Apple | 与Apple ID原生集成，体验一致        |
| **Android**         | ✅ [Microsoft Authenticator](https://support.microsoft.com/zh-cn/account-billing/%E4%B8%8B%E8%BD%BDmicrosoft-authenticator-351498fc-850a-45da-b7b6-27e523b8702a) | 微软开发支持TOTP、MFA等多种功能              |
| **微信小程序**   | ✅ 微信小程序「腾讯身份验证器」           | 使用便捷，适合微信重度用户           |

### 如何启用TOTP？

1. 正确可信的TOTP应用。
2. 登录 [id.ustc.edu.cn](https://id.ustc.edu.cn)，进入“个人中心”。
3. 在“安全设置”中选择“动态因子”，按提示绑定。

---

## 什么是通行密钥？

通行密钥是使用设备存储的加密密钥进行无密码登录的认证方式。

更多资料：
[IEEE 安全性研究论文](https://doi.org/10.1109/SP46215.2023.10179454)

### 操作系统支持矩阵

| 操作系统     | 支持情况              | 额外配置               |
|--------------|-----------------------|------------------------|
| Windows 10+  | 支持                   | 启用Windows Hello      |
| macOS 13+    | 支持                   | 无                     |
| iOS 16+      | 支持                   | 使用“密码”应用         |
| Android 9+   | 支持                   | 无                     |
| 鸿蒙         | 部分支持               | 无                     |

目前功能正在测试中，可在“个人中心 - 安全设置”启用。

---