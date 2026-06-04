# 在校状态数据推送说明

本文档说明上游系统如何将人员在校状态数据写入数据库，以供查询接口读取。

## 数据流向

```
上游系统 → USER_ZKD 表 → v_user 视图 → 查询接口
```

查询服务通过数据库视图 `v_user` 读取数据，该视图直接查询 `USER_ZKD` 表，不再经过中间的导入表或批次管理流程。

## v_user 视图定义

```sql
CREATE VIEW v_user AS
SELECT zxzt, gid, "userId" AS userid
FROM "USER_ZKD"
WHERE ("isDeleted" = 1);
```

字段映射：

| 视图字段 | USER_ZKD 字段 | 接口字段 | 说明 |
| --- | --- | --- | --- |
| `gid` | `gid` | `gid` | 人员全局标识，一个 gid 可能对应多个 userid |
| `userid` | `userId` | `zjhm` | 身份标识，全局唯一 |
| `zxzt` | `zxzt` | `ryzxztdm` | 人员在校状态代码 |

## 更新方式

上游系统需要直接写入或更新 `USER_ZKD` 表，按 `userId` 做 upsert。

### 写入单条记录

```sql
INSERT INTO "USER_ZKD" (gid, "userId", zxzt, "isDeleted")
VALUES ('2200600958', 'P0529', '10', 1)
ON CONFLICT ("userId") DO UPDATE
SET gid = excluded.gid,
    zxzt = excluded.zxzt,
    "isDeleted" = excluded."isDeleted";
```

### 批量写入

推荐使用 PostgreSQL `COPY` 批量写入：

```bash
psql "$DATABASE_URL" <<'SQL'
CREATE TEMP TABLE tmp_import (
  gid text,
  userid text,
  zxzt text
) ON COMMIT DROP;

\copy tmp_import (gid, userid, zxzt) FROM 'status_data.csv' WITH (format csv, header true)

INSERT INTO "USER_ZKD" (gid, "userId", zxzt, "isDeleted")
SELECT gid, userid, zxzt, 1
FROM tmp_import
ON CONFLICT ("userId") DO UPDATE
SET gid = excluded.gid,
    zxzt = excluded.zxzt,
    "isDeleted" = excluded."isDeleted";
SQL
```

### 每日全量替换

如果需要每天全量替换，建议先写入临时表再交换：

```sql
BEGIN;

-- 将新数据写入临时表（结构与 USER_ZKD 一致）
CREATE TEMP TABLE user_zkd_new (LIKE "USER_ZKD") ON COMMIT DROP;
-- ... 将新数据导入 user_zkd_new ...

-- 标记旧数据为已删除
UPDATE "USER_ZKD"
SET "isDeleted" = 0
WHERE "userId" NOT IN (SELECT "userId" FROM user_zkd_new);

-- 合并新数据
INSERT INTO "USER_ZKD" (gid, "userId", zxzt, "isDeleted")
SELECT gid, "userId", zxzt, 1
FROM user_zkd_new
ON CONFLICT ("userId") DO UPDATE
SET gid = excluded.gid,
    zxzt = excluded.zxzt,
    "isDeleted" = 1;

COMMIT;
```

## 注意事项

- 写入后查询接口即刻生效，无需等待批次导入。
- 表名和字段名区分大小写，SQL 中需要使用双引号（`"USER_ZKD"`、`"userId"`、`"isDeleted"`）。
- `isDeleted = 1` 表示有效记录（未被删除），`isDeleted = 0` 表示已删除。删除记录时设为 `0` 即可，无需物理删除。
- 每日推送全量时，确保只变更发生过变化的记录，减少不必要的写入。
- 本流程不处理物理删除，需要彻底清除的记录请提前协商规则。