# 在校状态查询接口

在校状态查询接口用于授权系统按 `gid` 或 `zjhm` 查询人员在校状态代码。接口仅面向已开通的系统调用，不面向浏览器用户开放。

## 接入方式

调用方需要提前提供：

- 系统名称
- 固定出口 IP 或 IP 段
- 接口联系人

管理员开通后会为调用方配置访问 token 和 IP allowlist。调用方请求接口时需要同时满足：

- 请求头包含有效的 `Authorization: Bearer <token>`
- 请求来源 IP 在已登记的 allowlist 内

请妥善保管 token，不要写入前端代码、公开仓库或日志。

如有接入需求请联系 wf0229@ustc.edu.cn。

## 通用说明

接口基础路径：

```text
https://id.ustc.edu.cn/doc/api/
```

返回格式为 JSON。除健康检查外，业务接口均需要鉴权。

字段说明：

| 字段 | 说明 |
| --- | --- |
| `gid` | 人员全局标识。一个 `gid` 可能对应多个 `zjhm` |
| `zjhm` | 身份标识。`zjhm` 全局不重复 |
| `ryzxztdm` | 人员在校状态代码，接口按源数据原样返回 |

## 健康检查

```http
GET /doc/api/health
```

示例响应：

```json
{
  "ok": true
}
```

## 按 gid 查询

```http
GET /doc/api/status/by-gid/{gid}
Authorization: Bearer <token>
```

示例响应：

```json
{
  "gid": "2200600958",
  "items": [
    {
      "zjhm": "P0529",
      "ryzxztdm": "10"
    }
  ]
}
```

如果 `gid` 对应多个身份，`items` 会返回多条记录。

## 按 zjhm 查询

```http
GET /doc/api/status/by-zjhm/{zjhm}
Authorization: Bearer <token>
```

示例响应：

```json
{
  "gid": "2200600958",
  "zjhm": "P0529",
  "ryzxztdm": "10"
}
```

## 批量按 gid 查询

```http
POST /doc/api/status/by-gids
Authorization: Bearer <token>
Content-Type: application/json
```

请求体：

```json
{
  "gids": ["2200600958"]
}
```

示例响应：

```json
{
  "items": [
    {
      "gid": "2200600958",
      "items": [
        {
          "zjhm": "P0529",
          "ryzxztdm": "10"
        }
      ]
    }
  ],
  "not_found": []
}
```

批量按 `gid` 查询时，每个命中的 `gid` 返回一个对象；对象内的 `items` 是该 `gid` 对应的身份数组。

## 批量按 zjhm 查询

```http
POST /doc/api/status/by-zjhms
Authorization: Bearer <token>
Content-Type: application/json
```

请求体：

```json
{
  "zjhms": ["P0529"]
}
```

示例响应：

```json
{
  "items": [
    {
      "gid": "2200600958",
      "zjhm": "P0529",
      "ryzxztdm": "10"
    }
  ],
  "not_found": []
}
```

批量接口一次最多查询 100 条。超过 100 条的数据需求，请联系数据中心协商批量数据导出方案。

## 错误码

| HTTP 状态码 | 说明 |
| --- | --- |
| 401 | 缺少 token 或 token 无效 |
| 403 | token 有效，但来源 IP 不在 allowlist 内 |
| 400 | 请求参数不符合要求，例如批量查询超过 100 条 |
| 404 | 查询对象不存在 |
| 500 | 服务内部错误 |

错误响应示例：

```json
{
  "detail": "zjhm not found"
}
```

## 调用示例

以下示例使用 `<token>` 占位，调用时请替换为实际的 token。

### 按 zjhm 查询

```bash
curl -H "Authorization: Bearer <token>" \
  "https://id.ustc.edu.cn/doc/api/status/by-zjhm/P0529"
```

### 按 gid 查询

```bash
curl -H "Authorization: Bearer <token>" \
  "https://id.ustc.edu.cn/doc/api/status/by-gid/2200600958"
```

### 批量按 gid 查询

```bash
curl -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"gids": ["2200600958", "2200600959"]}' \
  "https://id.ustc.edu.cn/doc/api/status/by-gids"
```

### 批量按 zjhm 查询

```bash
curl -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"zjhms": ["P0529", "P0530"]}' \
  "https://id.ustc.edu.cn/doc/api/status/by-zjhms"
```

