# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知和公开公告。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告，以及维护者看不到协调员专用材料。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/fix-acceptances`、`POST /api/reports/{id}/fix-acceptances/{acceptance_id}`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。

## 修复验收

`fixing -> resolved` 必须经过两步：维护者通过 `/api/fix-acceptances` 提交当前修复计划的完成确认，协调员再通过 `/api/reports/{id}/fix-acceptances/{acceptance_id}` 确认通过。每条验收记录保存提交时的计划版本、计划内容与目标日期快照、双方说明和时间戳，报告详情中的 `fix_acceptances` 保留完整验收历史。维护者随后修改计划内容或目标日期会使计划版本递增、未完成的验收记录作废（`invalidated`）并通知协调员重新确认；报告从 `resolved` 回到 `fixing` 时验收同样失效。已作废的记录仍可查看，但不能再用于解决报告。
