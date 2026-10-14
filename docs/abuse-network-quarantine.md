# 违规行为识别与双向网络隔离

## 处理约定

仅在同一实例、同一进程 incarnation 的高置信度特征得到至少两次新鲜佐证，且间隔不少于 20 秒时，隔离涉事容器的受管入站和出站网络，保留容器、进程、磁盘和恢复记录，向已配置的 Telegram 管理机器人发送严重告警。隔离包含 SSH；排查从宿主机控制台进入。没有自动解除倒计时，流量消失、采样过期或管理员忽略告警都不解除隔离。

这不是“高连接数就封禁”：Python、Telegram、并发配置、TLS、代理流量或单一连接数指标均不构成隔离依据。原来的连接数过高持续一小时才处置策略不变。

## 当前识别证据与边界

- 运行中的已知对外扫描/认证爆破工具：实际可执行文件身份与目标参数匹配，排除帮助、被动列举、排除项、密码和源地址参数，再复核进程身份。当前工具规则只判定公网字面 IP/CIDR，不猜测目标文件或域名。
- 同一进程的异常公网 SYN-SENT 扇出：至少 32 个不同待连接端点、占比不少于 90%，且同 IP 至少 32 个目标端口，或敏感端口至少 64 个目标 IP；两次佐证。普通 80/443 CDN 扇出不符合横向扫描规则。
- Python 运行入口里的撞库、认证爆破、身份枚举组合特征：字典/生成器、循环、敏感字段、认证/身份接口和调用语义相互佐证；必须有同进程、与目标域名解析/IP 匹配的实时公网 HTTP/TLS 连接。机器人的 Telegram 轮询连接不能替代业务接口连接。
- 所有新隔离前重新检查进程 PID 与启动 ticks；实例操作绑定 Incus `volatile.uuid` 或 Podman 完整容器 ID。同名新实例不会继承旧实例隔离。

当前实现是有限规则的行为识别，不是对“所有黑灰产”的完整识别或法律定性。混淆/编译程序、动态导入、Python `-m`、自定义加密协议、HTTP CONNECT 代理、私网横向活动、缺失进程权限或无法对应目标解析时，不能凭空判定；仍需管理员调查和后续规则。不会解密 TLS，不会向第三方身份/登录接口发起验证请求，不扫描其他人的服务器。

Docker 保持项目原有仅提醒、不自动处置策略。Incus/Podman 的主机/共享网络、硬件直通等无法证明隔离完整性的拓扑会产生严重失败告警，要求人工隔离，绝不显示“已双向隔离”。必须结合实际部署审计这些覆盖缺口，不能把未检测到行为解释为无风险。

## 隔离及恢复

- Incus：仅修改涉事实例自身的网络/代理设备覆盖，不改共享 profile、桥、网络或磁盘。用 `none` 掩盖继承设备，使用 ETag 条件更新，等待操作成功并读回实例配置与原网卡状态。
- Podman：逐一断开涉事容器的全部受管网络；恢复时校验原网络、IPv4/IPv6、MAC 和别名。共享命名空间、host/rootless 特殊网络、特权和设备直通实例不冒险修改。
- 先落盘私有恢复 journal，再修改网络；重复检查会维持隔离。恢复失败保留记录并尝试重新隔离。
- 管理员在网页“违规活动隔离”卡片复核、二次确认后下发恢复指令。排队 ACK 不是恢复成功，节点结果不是风险复查通过；再命中会再次隔离。
- 采样失效/采集失败保留待复核事件，明确当前隔离状态待确认。Telegram 初次送达以实际 `message_id` 映射为凭据，不把服务端接收事件误作送达。

## 证据最小化

只读取运行入口的有界源码，源码/argv 在节点内存中分类；不读取个人身份历史、密码库、聊天内容或任意目录。上报/落盘只允许规则类型、PID/启动 ticks、文件 SHA256、计数和特征元数据，不包含源码、口令、身份记录或完整 URL 参数。

## 上线验证门槛

1. 全量单元测试、Linux 采集测试、前端构建、桌面/移动端交互和权限检查。
2. 用全新临时实验容器验证 IPv4/IPv6 入站/出站阻断、共享网络其他容器不受影响、容器/PID/磁盘保持、原网络和代理恢复。
3. 通过真实已配置 TG 目标发送明确标为演练的消息，不伪造客户违规事件。
4. Server 数据库在线备份/quick_check、可回滚升级、Agent 金丝雀后扩展；核实新鲜签名报告和隔离覆盖状态。完成这些门槛前，不宣称全网保护已上线。

演练脚本必须显式 `--run`，只使用本地已有镜像，只删除自己成功创建的精确随机资源名：

```sh
python3 scripts/verify-abuse-quarantine.py --run --image <existing-python-image>
python3 scripts/verify-abuse-incus.py --run --image <local-alpine-fingerprint> --pool <pool> --module client/network_quarantine.py
```

官方行为依据：[Incus none device](https://linuxcontainers.org/incus/docs/main/reference/devices_none/)、[Podman disconnect](https://docs.podman.io/en/stable/markdown/podman-network-disconnect.1.html)、[Podman reconnect options](https://docs.podman.io/en/stable/markdown/podman-network-connect.1.html)。实际可用性以目标宿主机演练为准。
