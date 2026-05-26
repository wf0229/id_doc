# 在校状态数据推送说明

本文档说明上游系统如何将人员在校状态数据推送到本地 PostgreSQL 数据库。

## 推送目标

上游系统每天推送一批变更数据，字段包括：

| 字段 | 说明 | 示例 |
| --- | --- | --- |
| `gid` | 人员全局标识 | `2200600958` |
| `zjhm` | 身份标识，同一批次内唯一 | `P0529` |
| `ryzxztdm` | 人员在校状态代码，原样写入 | `10` |

本服务按 `zjhm` 做增量 upsert。批次导入成功后，本批次中的记录会新增或覆盖正式查询表中的同 `zjhm` 记录；未出现在本批次中的旧记录保持不变。本流程不处理删除。

## 数据表

### 批次表

`identity_status_import_batch`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `version` | `bigint` | 批次号，建议使用日期时间编号，例如 `2026052601` |
| `status` | `text` | 批次状态：写入中为 `writing`，写完后改为 `ready` |
| `created_at` | `timestamptz` | 批次创建时间 |
| `ready_at` | `timestamptz` | 批次写完时间 |
| `row_count` | `integer` | 本批次行数 |

### 明细表

`identity_status_import`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `version` | `bigint` | 批次号 |
| `gid` | `text` | 人员全局标识 |
| `zjhm` | `text` | 身份标识，同一版本内唯一 |
| `ryzxztdm` | `text` | 人员在校状态代码 |
| `pushed_at` | `timestamptz` | 写入时间，由写入 SQL 填充 |

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

推荐使用 PostgreSQL `COPY` 批量写入，性能比逐条 `insert` 更好。为了让数据文件只包含业务字段，建议先 `COPY` 到临时表，再写入正式导入表并填充 `pushed_at`。

CSV 文件建议包含四列：

```text
version,gid,zjhm,ryzxztdm
2026052601,2200600958,P0529,10
```

使用 `psql` 导入：

```bash
psql "$DATABASE_URL" <<'SQL'
create temporary table identity_status_import_copy (
  version bigint,
  gid text,
  zjhm text,
  ryzxztdm text
) on commit drop;

\copy identity_status_import_copy (version, gid, zjhm, ryzxztdm) from 'identity_status.csv' with (format csv, header true)

insert into identity_status_import (version, gid, zjhm, ryzxztdm, pushed_at)
select version, gid, zjhm, ryzxztdm, now()
from identity_status_import_copy
on conflict (version, zjhm) do update
set gid = excluded.gid,
    ryzxztdm = excluded.ryzxztdm,
    pushed_at = excluded.pushed_at;
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

批次标记为 `ready` 后，管理员运行本地导入命令，将该批次变更 upsert 到正式查询表。

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

- 每次推送应使用新的 `version` 作为批次号。
- 每个批次只需要包含变更过的数据。
- 本流程只处理新增和更新，不处理删除；需要删除或失效记录时请提前协商字段和规则。
- 写入期间批次状态必须保持为 `writing`。
- 只有全部写入完成后才能将状态改为 `ready`。
- 不要直接写正式查询表 `identity_status`。
- 生产环境建议使用 `COPY` 或批量写入，不建议逐条提交。
