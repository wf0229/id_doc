# 中国科学技术大学 统一身份认证系统 开发者手册

本指南适用于校内应用系统开发者，帮助您对接统一身份认证（CAS / OAuth2.0 / OIDC）。

> ⚠️ 校外应用（不在校内部署、域名不为 `ustc.edu.cn`）目前不提供对接支持。

---

## 1. 概述

统一身份认证系统提供单点登录（SSO）能力，支持：

- **CAS 3.0**：[CAS Protocol 3.0 Specification](https://apereo.github.io/cas/7.1.x/protocol/CAS-Protocol-Specification.html)
- **OAuth 2.0**：[OAuth 2.0](https://oauth.net/2/) 中授权码模式（Authorization Code Grant）
- **OIDC 1.0**：[OpenID Connect 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

统一身份认证系统推荐通过 **OAuth2.0 授权码模式（Authorization Code Grant）** 接入。针对不同类型应用，对接前请做好准备：

- 网页应用：在[网络安全工作平台](https://netsecurity.ustc.edu.cn/)完成建站申请及网站备案后，由网站负责人或管理员填写[统一身份认证接入申请](https://service.ustc.edu.cn/fe/taskCenter/one/application?app_id=234)
- 公众号/小程序应用：[OA公文系统](https://e.ustc.edu.cn)完成新媒体备案后，联系[wf0229@ustc.edu.cn](mailto:wf0229@ustc.edu.cn)
- 移动APP：联系[wf0229@ustc.edu.cn](mailto:wf0229@ustc.edu.cn)

系统管理员收到应用接入申请后提供相关参数信息（如client_id&client_secret等）

## 2. 系统接口

### 2.1 OAuth2.0 接口

开始对接时，开发者需要获得 `client_id`、`client_secret`。

#### 第一步：第三方应用将用户认证重定向至统一身份认证

|Field          |Details                                                                                                |
|---------------|-------------------------------------------------------------------------------------------------------|
|**endpoint**   |`https://id.ustc.edu.cn/cas/oauth2.0/authorize`                                                        |
|**method**     |`GET`                                                                                                  |

重定向时，请提供相关参数：

|Parameter      |Required   |Example                                 |Description                        |
|---------------|-----------|----------------------------------------|-----------------------------------|
|response_type  |MUST       |`code`                                  | 固定值`code`，表示授权码模式        |
|client_id      |MUST       |`oauth_test_client_id`                  | 应用的 Client ID，由系统管理员提供  |
|redirect_uri   |MUST       |`https://webapp.ustc.edu.cn/callback`   | 授权完成后回调地址,需要urlencode    |
|scope          |OPTIONAL   |`gid email name`                        | 请求的权限范围，多个权限用空格分隔   |
|state          |OPTIONAL   |`xyz987`                                | 随机生成的字符串，用于防止CSRF攻击   |

示例代码：

```bash
curl https://id.ustc.edu.cn/cas/oauth2.0/authorize?response_type=code&client_id=oauth_test_client_id&redirect_uri=https%3A%2F%2Fwebapp.ustc.edu.cn%2Fcallback
```

统一身份认证接到请求后，会向**用户代理**（User Agent，即浏览器）展示登录页面。

用户提供有效登录凭据后，统一身份认证服务器向**用户代理**做出响应：

```http
HTTP/1.1 302 Found
Location: https://webapp.ustc.edu.cn/callback?code=ABCD1234&state=xyz123
```

其中:

|Parameter      |Example                            |Description                                          |
|---------------|-----------------------------------|-----------------------------------------------------|
|code           |`ABCD1234`                         |统一身份认证生成的随机字符串，用以下一步换取access_token |
|state          |`xyz987`                           |与request时候传递相同                                 |

值得注意的是：

- 一般情况下不需要传递 `scope`，统一身份认证系统会配置好每个webapp所需的用户属性并返回。
- 第三方应用需要必要的机制来预防CSRF(Cross-Site Request Forgery)，例如通过传递随机生成的 `state` 并校验，以避免统一身份认证的响应被劫持后导致会话混淆,即攻击者可以代替受害者与应用系统建立连接，详见 [How does CSRF work without state parameter in OAuth2.0?](https://stackoverflow.com/questions/35985551/how-does-csrf-work-without-state-parameter-in-oauth2-0/35988614#35988614)

#### 第二步：第三方应用使用 `code` 获取 `access_token`

第三方应用回调地址获取到 `code` 后，使用 `code` 获取 `access_token` 。

|Field                  |Details                                                                                        |
|-----------------------|-----------------------------------------------------------------------------------------------|
|**endpoint**           |`https://id.ustc.edu.cn/cas/oauth2.0/accessToken`                                              |
|**method**             |`POST`                                                                                         |

在获取 `access_token` 时，需要增加请求头:

```http
Content-Type: application/x-www-form-urlencoded
```

同时携带相关参数：

|Parameter      |Required   |Example                              |Description                            |
|---------------|-----------|-------------------------------------|---------------------------------------|
|grant_type     |MUST       |`authorization_code`                 | 授权模式固定值                         |
|client_id      |MUST       |`oauth_test_client_id`               | 应用的 Client ID，系统管理员提供        |
|client_secret  |MUST       |`9aggRf1kk0tS...`                    | 应用的 Client Secret，系统管理员提供    |
|redirect_uri   |MUST       |`https://webapp.ustc.edu.cn/callback`| 回调地址，需与第一步一致并URL编码        |
|code           |MUST       |`OC-9-iQBaj2rYndjtttJqJ`             | 从第一步授权返回的 code                 |

🌿 请求示例
```bash
curl -X POST "https://id.ustc.edu.cn/cas/oauth2.0/accessToken" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code" \
     -d "client_id=oauth_test_client_id" \
     -d "client_secret=9aggRf1kk0tS..." \
     -d "redirect_uri=http%3A%2F%2Fwebapp.ustc.edu.cn%2Fcallback" \
     -d "code=OC-9-iQBaj2rYndjtttJqJE9P6Qn-eoinZGnJ"
```

统一身份认证服务器在验证成功后将返回如下响应：

```json
{
    "access_token":"AT-98-kkxRFRAp7JP4HvKcooOlTjqEslglCNoU",
    "token_type":"bearer",
    "expires_in":28800
}
```

其中：

| Parameter    | Example                                  | Description                   |
| -------------| ---------------------------------------- | ----------------------------- |
| access_token | `AT-98-kkxRFRAp7JP4HvKcooOlTjqEslglCNoU` | 用于后续获取用户信息的访问令牌   |
| token_type   | `bearer`                                 | 令牌类型，固定为 `bearer`       |
| expires_in   | `28800`                                  | 有效期（单位：秒）             |

如果校验失败，错误代码解释如下：

| Parameter    | Example                                  | Description                   |
| -------------| ---------------------------------------- | ----------------------------- |

#### 第三步：第三方应用使用access_token获取用户信息

第三方应用在获取 `access_token` 后，需要使用该令牌调用接口获取用户信息。

| Field        | Details                                       |
| ------------ | --------------------------------------------- |
| **endpoint** | `https://id.ustc.edu.cn/cas/oauth2.0/profile` |
| **method**   | `POST`                                        |


在获取用户信息时，需要增加请求头:

```http
Content-Type: application/x-www-form-urlencoded
```

同时携带相关参数：

| Parameter    | Required | Example                                  | Description          |
| ------------ | -------- | ---------------------------------------- | -------------------- |
| access_token | MUST     | `AT-98-kkxRFRAp7JP4HvKcooOlTjqEslglCNoU` | 第二步获取的 access_token |


🌿 POST 请求示例

```bash
curl -X POST "https://id.ustc.edu.cn/cas/oauth2.0/profile" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "access_token=AT-98-kkxRFRAp7JP4HvKcooOlTjqEslglCNoU"
```

统一身份认证服务器在验证成功后将返回如下响应：

```json
{
    "active": true,
    "attributes": {
        "deptCode": "304",
        "email": "zhangsan@mail.ustc.edu.cn",
        "gid": "9202420483",
        "jrzjhm": "45433",
        "login": "45433",
        "loginip": "117.152.207.90",
        "logintime": "2025-05-20 22:48:42",
        "name": "张三",
        "objectId": "673493032d5b870006ebcf85",
        "ryfldm": "102010000",
        "ryzxztdm": "10",
        "xbm": "1",
        "zjhm": "45433"
    },
    "id": "45433",
    "client_id": "xxx"
}
```

返回参数说明：

| Parameter  | Description      | Dictionary Reference |
| ---------- | ---------------- | -------------------- |
| id         | 用户名              | 无                    |
| client_id | 应用 ID            | 无                    |
| attributes | 用户属性列表           | 无                    |
| deptCode   | 部门编码             | 无                    |
| email      | 邮箱               | 无                    |
| gid        | GID              | 无                    |
| login      | 用户输入的账号（GID或学工号） | 无                    |
| loginip    | 登录 IP            | 无                    |
| logintime  | 登录时间             | 无                    |
| name       | 姓名               | 无                    |
| ryfldm     | 人员类型代码           | 有                    |
| ryzxztdm   | 在校状态码            | 有                    |
| xbm        | 性别码              | 有                    |
| zjhm       | 证件号码（学工号）        | 无                    |

⚠️ **安全提示：**

- `access_token`是敏感凭据，请勿在客户端或日志中暴露。
- 如需了解人员类型、性别等字典对应关系，请联系系统管理员获取完整数据字典。

#### 额外一步：第三方应用获取用户多身份信息

第三方应用在获取 `access_token` 后，可使用该令牌调用接口获取用户的单/多身份信息。

| Field        | Details                                                           |
| ------------ | ----------------------------------------------------------------- |
| **endpoint** | `https://id.ustc.edu.cn/cas/oauth2.0/oauthcode/multiple/identity` |
| **method**   | `POST`                                                            |

同样的，需要增加请求头:

```http
Content-Type: application/x-www-form-urlencoded
```

请求参数：

| Parameter     | Required | Example                                  | Description          |
| ------------- | -------- | ---------------------------------------- | -------------------- |
| access_token  | MUST     | `AT-98-kkxRFRAp7JP4HvKcooOlTjqEslglCNoU` | 第二步获取的 access_token |


🌿 POST 请求示例

```bash
curl -X POST "https://id.ustc.edu.cn/cas/oauth2.0/oauthcode/multiple/identity" \
     -H "Content-Type: multipart/form-data" \
     -F "access_token=AT-98-kkxRFRAp7JP4HvKcooOlTjqEslglCNoU"
```
统一身份认证服务器在验证成功后将返回如下示例（以“主任”和“组长”多身份为例）：

```json
{
    "id": "45433",
    "users": [
        {
            "xbm": "1",
            "ryzxztdm": "10",
            "gid": "9202420483",
            "email": "zhangsan@mail.ustc.edu.cn",
            "ryfldm": "102010000",
            "name": "张三",
            "jrzjhm": "45433",
            "zjhm": "45433",
            "deptCode": "304"
        },
        {
            "xbm": "1",
            "gid": "9202420483",
            "name": "张三",
            "jrzjhm": "9202420483",
            "zjhm": "U0125095"
        }
    ]
}
```

返回参数说明：

| Parameter | Description        | Dictionary Reference |
| --------- | ------------------ | -------------------- |
| id        | 用户名                | 无                    |
| users     | 用户身份数组，每个元素为一组身份信息 | 无                    |

`users` 数组中字段说明：

| Field    | Description | Dictionary Reference |
| -------- | ----------- | -------------------- |
| xbm      | 性别码         | 有                    |
| ryzxztdm | 在校状态码       | 有                    |
| gid      | GID         | 无                    |
| email    | 邮箱          | 无                    |
| ryfldm   | 人员类型代码      | 有                    |
| name     | 姓名          | 无                    |
| jrzjhm   | 进入人主键（或学工号） | 无                    |
| zjhm     | 证件号码（学工号）   | 无                    |
| deptCode | 部门编码        | 无                    |


⚠️ 安全提示：
- `access_token` 为敏感凭据，请勿在客户端或日志中暴露。
- 如果同一用户存在多个身份（如主任、组长），将以数组形式返回，需由应用自行选择或提示用户确认。

### 2.2 CAS 3.0 接口

#### 第一步：应用请求用户认证

应用向统一身份认证（CAS）服务器发起认证请求。

| Field        | Details                            |
| ------------ | ---------------------------------- |
| **endpoint** | `https://id.ustc.edu.cn/cas/login` |
| **method**   | `GET`                              |

请求参数：

| Parameter | Required | Example                                      | Description                 |
| --------- | -------- | -------------------------------------------- | --------------------------- |
| service   | MUST     | `	https%3A%2F%2Fwebapp.ustc.edu.cn%2Flogin%2Fcas_login` | 用户认证成功后，CAS将携带Ticket重定向回该地址，要求URLENCODE |
| renew     | OPTIONAL | `True` | 如果设置此参数，SSO 单点状态将被绕过。在这种情况下，无论CAS是否存在SSO session，CAS都要求客户端提供凭证。 |
| gateway   | OPTIONAL | `True` | 如果设置了此参数，则CAS不会要求客户端提供凭据。 |

- 注意不要同时设置 `renew`和`gateway`参数，两者都设置统一身份认证服务器会忽略`gateway`。
- `gateway`为Ture时：
  * 如果用户代理与统一身份认证服务器已经存在单点会话（session），统一身份认证服务器会将用户代理重定向到service指定的URL，并附加一个有效的`ticket`。
  * 如果用户代理与统一身份认证服务器尚不存在单点会话（session），统一身份认证服务器会将用户代理重定向到service指定的URL。
- 中国科大统一身份认证服务器`/login`接口不支持`method`参数

🌿 请求示例

```bash
curl "https://id.ustc.edu.cn/cas/login?service=https%3A%2F%2Fwebapp.ustc.edu.cn%2Flogin%2Fcas_login"
```

统一身份认证接到请求后，会向**用户代理**（User Agent，即浏览器）展示登录页面。

用户提供有效登录凭据后，统一身份认证服务器向**用户代理**做出响应：

```http
HTTP/1.1 302 Found
Location: https://webapp.ustc.edu.cn/login/cas_login?ticket=ST-368-gChqIqVuq9j83YCG9dw4sh1KDaMrg-sso-fddcfb8db-z9ng2
```

参数说明：

| Parameter | Example                                                    | Description                       |
| --------- | ---------------------------------------------------------- | --------------------------------- |
| ticket    | `ST-368-gChqIqVuq9j83YCG9dw4sh1KDaMrg-sso-fddcfb8db-z9ng2` | Service Ticket，用于下一步向CAS服务器验证用户身份 |

⚠️ **说明：**

- `ticket`只在**一次性验证**有效，使用后立即失效。
- **Service URL**必须与后续验证请求中的`service`参数保持一致,且必须URLENCODE。

#### 第二步：验证 Ticket（CAS 3.0 协议）

应用在收到 ticket 后，需要向统一身份认证服务器验证票据以获取用户信息。

| Field        | Details                                         |
| ------------ | ----------------------------------------------- |
| **endpoint** | `https://id.ustc.edu.cn/cas/p3/serviceValidate` |
| **method**   | `GET`                                           |

请求参数：

| Parameter | Required | Example                                                    | Description                     |
| --------- | -------- | ---------------------------------------------------------- | ------------------------------- |
| ticket    | MUST     | `ST-368-gChqIqVuq9j83YCG9dw4sh1KDaMrg-sso-fddcfb8db-z9ng2` | 第一步认证后返回的 Service Ticket        |
| service   | MUST     | `https%3A%2F%2Fwebapp.ustc.edu.cn%2Flogin%2Fcas_login`     | 与第一步完全一致的 Service URL（需 URLENCODE） |
| format    | OPTIONAL | `JSON` 或 `XML`     | 选择返回信息的数据结构 |

统一身份认证服务器默认返回xml结构：

```xml

```

如果传递了`formate=json`，则返回`json`格式数据

```json
{
    "active": true,
    "attributes": {
        "deptCode": "304",
        "email": "zhangsan@mail.ustc.edu.cn",
        "gid": "9202420483",
        "jrzjhm": "45433",
        "login": "45433",
        "loginip": "117.152.207.90",
        "logintime": "2025-05-20 22:48:42",
        "name": "张三",
        "objectId": "673493032d5b870006ebcf85",
        "ryfldm": "102010000",
        "ryzxztdm": "10",
        "xbm": "1",
        "zjhm": "45433"
    },
    "id": "45433",
    "client_id": "xxx"
}
```

参数说明：

| Element  | Example                     | Description |
| -------- | --------------------------- | ----------- |
| user     | `zhangsan`                  | 用户名         |
| email    | `zhangsan@mail.ustc.edu.cn` | 邮箱地址        |
| name     | `张三`                        | 姓名          |
| gid      | `9202420483`                | GID         |
| deptCode | `304`                       | 部门编码        |
| ryfldm   | `102010000`                 | 人员类型代码      |
| ryzxztdm | `10`                        | 在校状态码       |
| xbm      | `1`                         | 性别码         |
| zjhm     | `45433`                     | 证件号码（学工号）   |

⚠️ 说明：

- Service URL必须与第一步完全一致（包括协议、域名、路径、URL编码）。
- 返回的XML需由应用解析，提取 authenticationSuccess 元素下的用户信息。
- 如果验证失败，返回 <cas:authenticationFailure>。

### 2.3 OIDC 1.0 接口

TBC

### 2.4 单点登出

当应用需要让用户退出登录时，可调用统一身份认证服务器的退出接口。注意，这里会注销用户代理（即浏览器）的单点会话状态（session）。

| Field        | Details                             |
| ------------ | ----------------------------------- |
| **endpoint** | `https://id.ustc.edu.cn/cas/logout` |
| **method**   | `GET`                               |

请求参数：

| Parameter | Required | Example                                                | Description                  |
| --------- | -------- | ------------------------------------------------------ | ---------------------------- |
| service   | OPTIONAL | `https%3A%2F%2Fwebapp.ustc.edu.cn%2Flogin%2Fcas_login` | 用户登出后，CAS会自动重定向到指定地址（需URL编码） |

如果`logout`时不设置`service`，登出后用户代理会停留在`https://id.ustc.edu.cn`

### 2.5 字典表

#### 用户信息

| 参数         | 说明                                       | 是否有字典 |
|--------------|------------------------------------------|------------|
| id           | 用户名                                     | 否         |
| client_id    | 应用ID                                    | 否         |
| attributes   | 用户属性列表                               | 否         |
| deptCode     | 部门编码                                   | 否         |
| email        | 邮箱                                      | 否         |
| gid          | GID                                      | 否         |
| login        | 登录时输入的账号（用户输入的GID或学工号）    | 否         |
| loginip      | 登录的IP                                  | 否         |
| logintime    | 登录的时间                                 | 否         |
| name         | 姓名                                      | 否         |
| ryfldm       | 人员类型代码                                | 是         |
| ryzxztdm     | 在校状态码                                 | 否         |
| xbm          | 性别码                                    | 是         |
| zjhm         | 证件号码（学工号）                          | 否         |

#### 人员类型代码字典表

邮件联系[wf0229@ustc.edu.cn](mailto:wf0229@ustc.edu.cn)获取。

#### xbm字典表
| 代码 | 字典值  |
|------|--------|
| 1    | 男     |
| 2    | 女     |

#### ryzxztdm字典表
| 代码 | 字典值  |
|------|--------------------------|
| 10    | 在校                    |
| 20    | 离校(含校内身份结束)     |
| 30    | 校内身份转换               |
| 40    | 离退休                    |
| 50    | 暂时离校(休学/出国等)     |
| 99    | 其他                    |
| 91    | 证件停用或注销          |

---

## 3 网页应用接入示例

TBC

---
