# 一些安全相关的设置更新

## [2024-12-11] 🚨 认证系统不再支持 TLS 1.0 & 1.1

各应用系统管理员、开发者：

统一身份认证系统将在新版本更新后**移除对 TLS 1.0 和 1.1 的支持**（依据 [RFC8996](https://datatracker.ietf.org/doc/html/rfc8996)），同时增加对 TLS 1.3 的支持。

如有疑问，请联系[wf0229@ustc.edu.cn](mailto:wf0229@ustc.edu.cn)

### 🌿 你可以在服务器测试支持情况

```bash
# 测试 TLS 1.2
curl -v --tlsv1.2 https://passport.ustc.edu.cn/healthcheck

# 测试 TLS 1.3
curl -v --tlsv1.3 https://passport.ustc.edu.cn/healthcheck
```

---