# 个人经营分析

登录后打开“经营分析”，输入 Narwhal 平台个人 API Key，保存并同步。
这不是全局买家通知的密钥；各 Dashboard 用户独立配置、独立查看。
只执行上游 GET，不创建小鸡、购买、退款、改价或发送通知。

## 密钥与部署

- `server/requirements.txt` 新增 cryptography；容器镜像包含 commerce.py。
- 默认在 DB_PATH 同目录自动创建 `.commerce-secret.key`，Linux 权限必须为 0600。生产 `/data` 必须是持久卷；保留数据库和主密钥的独立、受限备份。
- 也可注入 `COMMERCE_ENCRYPTION_KEY`（Fernet 主密钥，32 字节 URL-safe base64）。不要写进 Git。切换主密钥前需要迁移现有密文，否则必须重新输入个人 API Key。
- Windows 本地开发应限制数据目录 ACL；0600 不能替代 Windows ACL。
- SQLite 仅存 Fernet 密文，不返回原始或加密后的密钥、不记入请求审计。浏览器不保存到 localStorage/sessionStorage。
- 删除用户同时删除其个人密钥和快照。登录密码改变会使旧个人配置不可见，需重新配置，防止删除/重建同名账号继承凭据。
- 删除个人密钥同时清除应用可访问的缓存，不修改上游资源。SQLite 历史备份/WAL 可能仍含密文及历史快照，按既有备份保留策略管理；不声称安全擦除。

## 来源与口径

文档： https://api.fuckip.me/openapi.yaml
固定上游： https://api.fuckip.me/api/v1 ，不允许用户自定义出口或重定向转发密钥。

| 视图 | 数据源 | 口径 |
| --- | --- | --- |
| 账号余额 | GET /user/me | USD；可提现、托管、托管冻结分开显示，不推断净利润 |
| 母鸡现状 | GET /machines 与 /machines/{id}/vms | 仅 owner_id 等于个人账号；当前归属其他用户的小鸡与自用小鸡分开计数，不当累计销量 |
| 收益对比 | /machines 的 est_revenue、earned_revenue、locked_value | 直接展示平台值，缺失为未提供；已结算收益不含退款、补偿和进行中的冻结值 |
| 订单历史 | GET /billing/orders | 仅当前账号的购买/退款/续费等订单；不声称覆盖所有买家历史。只有 status=completed 的金额进入汇总；状态缺失/其他状态不计入金额 |
| 账单流水 | GET /billing/transactions | 仅当前账号；保留金额原始符号；按类型和余额账户分别汇总，不与订单相加 |
| 母鸡归属 | 订单或流水 data.machine_id；订单缺失时按当前 VM ID 关联 | 历史字段优先。无法可靠映射时明确归属未知，不分析 note 文本猜归属 |

2026-10-13 只读核验实际接口确认：订单还包含 `status`、`machine_owner_id`、`data.machine_id` 和 `data.machine_name`；流水有 `data.machine_id`。这些字段比当时公开 YAML 更完整。仅采纳 ID/名称等白名单，不保存整个 data、credentials、agent_token、邮件、支付资料或 note。

历史筛选作用于记录、总数、类型金额、UTC 每日笔数及分页；不影响“当前母鸡/余额快照”。类型金额使用 Decimal 计算，前端仅格式化。走势图仅展示有记录的 UTC 日期，非连续等距日历时间序列。
账单流水笔数（如托管扣减）不是售出小鸡数量，扣减也不必然是退款。没有完整卖家订单契约时，不从流水反推累计销量或退款率。

## 同步与限制

手动同步为后台任务，页面轮询状态，刷新后继续读取进度，避免代理请求超时。每次成功才原子替换完整快照，失败保留旧数据并显示错误/过期。
新密钥清空旧缓存，修订号/任务号防止旧任务覆盖新密钥或已删除用户的数据。
账单使用固定 end_time 减少同步时新增流水导致的分页漂移；每个任务最多 4 个并发网络请求，短暂连接/429/502/503/504 失败只读重试一次。重复 ID、总数漂移、页缺失、无效金额/身份、响应超限均失败，不展示部分结果为完整历史。
单个列表最多 10000 条，总响应最多 20 MB，最多 250 请求，180 秒网络预算；每个同步任务最多 4 个并发连接，暂时性连接错误最多重试一次。超过上限明确报错，不能声称历史已全部同步。任务超过 240 秒可重试；快照超过 15 分钟标为过期。
快照仅代表一次同步期间的上游读结果，不是跨接口事务一致的会计账本。

## 本地检查

Python: `python -m unittest discover -s tests -p test_commerce.py`
前端: `cd frontend` 后执行 `npm run build`。
合成数据预览不接生产或上游，参见 tests/commerce_preview.py。
