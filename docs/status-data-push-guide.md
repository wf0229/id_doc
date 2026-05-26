# 在校状态数据推送说明

本文档说明上游系统如何将人员在校状态数据推送到本地 PostgreSQL 数据库。

## 推送目标

上游系统每天推送一批完整快照数据，字段包括：

| 字段 | 说明 | 示例 |
| --- | --- | --- |
| `gid` | 人员全局标识 | `2200600958` |
| `zjhm` | 身份标识，同一批次内唯一 | `P0529` |
| `ryzxztdm` | 人员在校状态代码，原样写入 | `10` |

本服务使用版本切换机制。上游写入新版本时，线上查询仍使用旧版本；新版本导入成功后，查询接口一次性切换到新版本。

## 数据表

### 批次表

`identity_status_import_batch`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `version` | `bigint` | 数据版本号，建议使用日期时间编号，例如 `2026052601` |
| `status` | `text` | 批次状态：写入中为 `writing`，写完后改为 `ready` |
| `created_at` | `timestamptz` | 批次创建时间 |
| `ready_at` | `timestamptz` | 批次写完时间 |
| `row_count` | `integer` | 本批次行数 |

### 明细表

`identity_status_import`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `version` | `bigint` | 数据版本号 |
| `gid` | `text` | 人员全局标识 |
| `zjhm` | `text` | 身份标识，同一版本内唯一 |
| `ryzxztdm` | `text` | 人员在校状态代码 |
| `pushed_at` | `timestamptz` | 写入时间 |

主键为 `(version, zjhm)`。同一个版本内，如果重复写入同一个 `zjhm`，应以后写入的数据为准。

## 推荐推送流程

### 1. 创建批次

```sql
insert into identity_status_import_batch (version, status, created_at, row_count)
values (2026052601, 'writing', now(), 0)
on conflict (version) do update
set status = 'writing',
    row_count = 0,
    ready_at = null;
```

### 2. 写入明细数据

推荐使用 PostgreSQL `COPY` 批量写入，性能比逐条 `insert` 更好。

CSV 文件建议包含四列：

```text
version,gid,zjhm,ryzxztdm
2026052601,2200600958,P0529,10
```

使用 `psql` 导入：

```bash
psql "$DATABASE_URL" <<'SQL'
\copy identity_status_import (version, gid, zjhm, ryzxztdm) from 'identity_status.csv' with (format csv, header true)
SQL
```

如果无法使用文件，也可以批量 `insert`：

```sql
insert into identity_status_import (version, gid, zjhm, ryzxztdm, pushed_at)
values
  (2026052601, '2200600958', 'P0529', '10', now())
on conflict (version, zjhm) do update
set gid = excluded.gid,
    ryzxztdm = excluded.ryzxztdm,
    pushed_at = now();
```

### 3. 标记批次 ready

全部明细写入完成后，执行：

```sql
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

批次标记为 `ready` 后，本地导入程序会将该版本切换为线上查询版本。

## 完整示例

```sql
insert into identity_status_import_batch (version, status, created_at, row_count)
values (2026052601, 'writing', now(), 0)
on conflict (version) do update
set status = 'writing',
    row_count = 0,
    ready_at = null;

insert into identity_status_import (version, gid, zjhm, ryzxztdm, pushed_at)
values (2026052601, '2200600958', 'P0529', '10', now())
on conflict (version, zjhm) do update
set gid = excluded.gid,
    ryzxztdm = excluded.ryzxztdm,
    pushed_at = now();

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

## 注意事项

- 每次推送应使用新的 `version`。
- 每个版本应是一份完整快照，而不是增量。
- 写入期间批次状态必须保持为 `writing`。
- 只有全部写入完成后才能将状态改为 `ready`。
- 不要直接写正式查询表 `identity_status`。
- 生产环境建议使用 `COPY` 或批量写入，不建议逐条提交。
