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

## 错误码

| HTTP 状态码 | 说明 |
| --- | --- |
| 401 | 缺少 token 或 token 无效 |
| 403 | token 有效，但来源 IP 不在 allowlist 内 |
| 404 | 查询对象不存在 |
| 500 | 服务内部错误 |

错误响应示例：

```json
{
  "detail": "zjhm not found"
}
```

## 调用示例

```bash
curl -H "Authorization: Bearer <token>" \
  "https://id.ustc.edu.cn/doc/api/status/by-zjhm/P0529"
```

## 数据更新

接口数据由上游系统推送到本服务 PostgreSQL 的导入表。导入采用版本切换机制：上游写入新版本时，线上查询继续使用旧版本；新版本导入成功后，接口一次性切换到新版本。导入失败时，旧版本继续可用。

### 导入表

上游系统写入 `identity_status_import`：

| 字段 | 说明 |
| --- | --- |
| `version` | 本次数据版本号，建议使用日期时间编号，例如 `2026052601` |
| `gid` | 人员全局标识 |
| `zjhm` | 身份标识，同一版本内不重复 |
| `ryzxztdm` | 人员在校状态代码 |
| `pushed_at` | 写入时间，默认由数据库生成 |

上游系统还需要维护批次状态表 `identity_status_import_batch`：

| 字段 | 说明 |
| --- | --- |
| `version` | 数据版本号 |
| `status` | 批次状态，写入中为 `writing`，写完后改为 `ready` |
| `row_count` | 本批次行数 |

### 上游写入流程

```sql
insert into identity_status_import_batch (version, status, created_at, row_count)
values (2026052601, 'writing', now(), 0);

insert into identity_status_import (version, gid, zjhm, ryzxztdm, pushed_at)
values (2026052601, '2200600958', 'P0529', '10', now());

update identity_status_import_batch
set status = 'ready',
    ready_at = now(),
    row_count = (
      select count(*)
      from identity_status_import
      where version = 2026052601
    )
where version = 2026052601;
```

生产环境推荐上游使用 PostgreSQL `COPY` 或批量写入，不建议逐条提交。

### 本地导入

批次状态为 `ready` 后，在 API 容器中执行：

```bash
docker compose exec school-status-api \
  python -m school_status_api.import_version 2026052601
```

导入命令会在事务中完成：

- 从 `identity_status_import` 导入该版本数据到正式查询表
- 将该版本设为当前 active version
- 标记批次为 `active`
- 清理旧版本查询数据和旧版本导入数据
