# Narwhal Cloud Container Watcher (CS)

当前版本：**v1.7.119**（Server 与 Client 共用仓库根目录的 `VERSION`）。

### v1.7.119：无 Git 探针自动更新与 GFW 任务恢复

- Agent 自动更新和管理员托管升级新增固定 GitHub 上游的归档模式：当 Git 不存在或 GitHub smart-HTTP 不可用时，通过 HTTPS 获取 main 对应的固定提交归档；校验提交、版本号、归档路径、文件类型与展开大小后才运行安装器，不覆盖本机仓库或其他文件。
- 无 Git checkout 的 Agent 现在可以正确上报托管升级能力；若发布期间 main 已变化，升级会安全失败并写回执，要求生成新的升级任务。
- 生产核查发现两个国内 GFW 探针停在 1.7.112，尚未包含 1.7.117 引入的 GFW 探测任务执行/失败回报逻辑，导致服务端任务排队后到期。本版修复其更新通道；探针升级并上报后才能确认 GFW 检测恢复，未完成的采样仍显示“待评估”。
- VMess 配置与进程启动时间核验改为在容器自身的 time namespace 内读取 `/proc/uptime` 与进程启动 tick，避免把隔离时钟与宿主机启动时钟混用；仍要求同一 namespace、稳定实时时钟且配置明确早于进程启动。待核实告警优先显示对应 PID 的具体扫描原因，不会因诊断优化放宽封锁条件。

### v1.7.118：修复探针托管升级缺少仓库配置

- 从压缩包或远程安装脚本安装、没有本地 Git checkout 的节点，安装器现在会在 `/opt/narwhal-monitor/<端类型>-update-repo` 建立固定上游的干净 checkout，再启用自动更新；已有路径或来源异常时保留现场，不覆盖。
- Agent 只有在更新脚本、systemd-run、Git、本地 checkout 与固定上游来源均可用时才报告支持托管升级，避免把永远无法更新的节点加入发布队列。
- Client 升级预检失败（如缺少 checkout、上游不符、main 已变化或本地修改）会写入失败回执；服务端不再等到 30 分钟超时才发现。

### v1.7.117：修复 GFW 探针身份校验并说明 VMess 待核实原因

- GFW TCP 探测任务现在按 UUID 校验任务/周期 ID，同时接受服务端实际使用的主机名与 32 位 Agent 节点 ID；修复任务被领取后因目标身份格式不匹配而未执行、最终超时的问题。
- Agent 遇到运行环境、任务校验或探测执行错误时，会使用已签名任务租约回报白名单错误码；安全告警会显示探针失败或超时原因，未知样本仍不会计为 GFW 阻断或恢复。
- VMess 进程扫描不完整时，告警逐项显示实际原因（例如进程时钟不可比较或进程代次缺失）；没有检测到 VMess 配置的普通不完整扫描不会被升级成 VMess 入站告警。
- VMess 端口仍只在配置、进程与监听证据完整匹配时阻断；本版本不通过降低证据门槛来消除待核实状态。

### v1.7.116：增加 CPU 与磁盘 I/O 阶梯保护

- 容器 CPU 持续达到配额的 90%（或单核 90%）且宿主机 CPU 忙碌达到 80%，连续确认 10 分钟后按原有效 CPU 容量的 50% 限制；之后每持续 5 分钟仍达到保护阈值，逐级降至 25% 和 10%。容器 CPU 使用低于当前限额的一半、主机忙碌低于 70% 并持续 10 分钟后，自动恢复原配额。
- 磁盘保护仅用于可验证的 cgroup v2 容器 I/O 归属：单块设备繁忙达到 80%、容器承担该设备至少 50% 的 I/O，且达到 10 MiB/s 或 250 IOPS，持续 5 分钟后，按触发时各方向读写基线的 50%、25%、10% 逐级收紧。每台宿主机最多自动限制一个容器；设备繁忙低于 60%、容器各受限方向低于当前限额一半并持续 10 分钟后，恢复原 `io.max`。
- CPU 使用 Incus / Podman 容器配额，磁盘 I/O 使用容器 cgroup 的 `io.max`。任何归属、读回或可恢复状态无法确认时不新增限制；触发与升级会发送资源保护通知，不将资源占用定性为客户滥用。

### v1.7.115：收紧 VMess 证据并修复限速与防火墙切换

- 容器限速前核对完整的 Incus / Podman 运行实例清单（包含未纳入监控的实例），确认目标网络命名空间未与其他容器或宿主机共享；清单不完整或身份变化时拒绝应用，避免误伤同网卡业务。
- VMess 自动封锁要求配置文件修改与变更时间都明确早于当前进程启动，并且进程和采集器具有可比较的时钟依据；配置证据不足时继续提示待核实，不新增封锁。
- 母机防火墙页面忽略已切换主机或范围的过期读回，策略加载期间禁止编辑，保存和恢复期间锁定目标；手工 RFW 规则仍需新鲜读回与逐条确认后才能删除。

### v1.7.114：解释防火墙读回故障并精简总览遥测

- Runman / RFW 读回失败会显示明确原因（如 socket 缺失、权限拒绝、接口超时或返回格式不兼容）及对应排查方向；只保存白名单原因码，不透传原始异常内容。
- RFW 暂时不可读时继续保留最近一次成功规则快照，同时明确标记为历史留存，不能当作当前生效证明。
- 总览主机网络与安全遥测改为默认收起，摘要显示告警与审计数量；展开后可搜索主机并每页查看 4 台详情，减少长页面占用。

### v1.7.113：完善 VMess 取证、限速状态与防火墙规则迁移

- VMess 配置目录扫描纳入符号链接配置文件；读取前后核对文件元数据，配置在扫描期间被替换时标记取证不完整，不据此新增封锁。
- 总览按风险筛选结果分页展示母机，默认只展开前三台有风险的母机；展开/折叠按钮明确作用于当前页，搜索也支持用户邮箱与内部备注。
- 带宽限速状态区分已保存但 Agent 尚未应用的策略，并按 Agent 版本解释 `tc` 优先级冲突；列表继续展示已读回的活动限速值。
- RFW 页面可把新鲜读回中的单条手工规则复制到单机网页策略草稿；原规则保留，待新规则保存并读回确认后再手动删除，降低迁移中断风险。

### v1.7.112：隐藏 Agent 安装摘要中的共享密钥

- Client 安装结束摘要不再输出共享密钥，只说明密钥已写入权限受限的本机配置文件。

### v1.7.111：支持不安装容器运行时的主机探针

- Client 安装器新增 `NARWHAL_ALLOW_NO_RUNTIME=1` 开关。没有 Docker、Podman 或 Incus 的主机可继续安装宿主机 Agent，而不自动安装 Podman。
- 作为连通性探针时，将 `Container runtimes` 设为 `none`，避免采集无关的容器运行时；Agent 仍以宿主机 systemd 服务运行，并使用宿主机网络命名空间执行已签名的 TCP 探测任务。
- 普通安装默认行为不变：未检测到容器运行时时仍会安装 Podman。

### v1.7.108：紧凑展示 GFW 状态与容器协议端口

- 总览主机遥测改为等高响应式状态卡；国内/海外连通性状态与持续、恢复、正常天数及累计阻断次数可直接查看，详细探测证据和恢复历史收进展开面板。
- 容器卡片明确标注“协议端口”，按协议统计不同监听端口数；只有配置与当前进程、端口匹配，或有对应的协议探测证据时才显示，未知协议继续标记待核实。

### v1.7.107：修复高连接数告警把缺失取证显示为 0

- 活动告警、告警历史、容器诊断时间线与 Telegram 深度取证现在根据 socket 快照覆盖状态显示方向及进程归属；连接数很高但没有逐连接样本时显示“未采集”，不再显示本机/远端/未知均为 0。
- 深度取证回执优先合并告警连接数与归属摘要中的预期连接数，避免旧版或字段缺失时将空 socket 快照误判为完整零值。
- 明确区分“当前没有连接”和“连接存在但无法采集归属证据”；conntrack 不可用时保留可见的 socket 状态证据说明。

### v1.7.106：修复 GFW 监控服务端模块未进入容器镜像

- 服务端镜像现在包含 `gfw_monitor.py`，修复镜像启动烟测中的模块导入失败，并确保跨区域连通性 API 随 Server 一起发布。

### v1.7.105：修复 GFW 探测模块的 Agent 更新打包检查

- Agent 更新器继续单独编译检查并备份新增的 `gfw_probe.py`，同时保持既有模块打包循环的兼容格式，避免升级发布检查误报失败。

### v1.7.104：新增跨区域国内连通性跟踪与容器协议端口摘要

- 可在公开测速配置页指定国内与海外探测节点；Agent 仅探测系统发现的宿主机公网 IPv4 上明确映射的 Incus / Podman TCP 端口，不猜测 NAT 地址或容器私网端口。
- 同一 IP/端口需连续 3 轮满足“至少 2 个国内探测点失败、海外探测点成功”才记录为疑似 GFW 阻断；同一阻断端点连续 2 轮恢复后结束本次周期，并记录阻断时长、恢复后的正常时长与历史次数。
- 探测点不足、样本过期、结果不一致或公网 IP/端口变化时显示待评估/待复核；未知样本不计入阻断或恢复时长。跨区域 TCP 结果是连通性证据，不单独证明具体封锁来源。
- 容器卡片在服务/代理摘要中按已确认的进程与监听端口证据展示各协议的不同端口数；未能确认协议时不猜测。

### v1.7.103：修复高连接数取证缺失与未知值误显示为 0

- 常规采样现在会随报告上报逐连接方向、进程/PID 归属和 conntrack 证据摘要；高连接数但容器内 `ss` 返回空列表时，会对 Incus/Podman 容器使用宿主机 `/proc` 做有界回退采样。
- 告警深度采样也会在 `ss` 成功但没有连接行时触发同一回退。仍未采到 socket 时明确标记证据不可用，并记录空快照原因，不把“未采到”解释成无连接或无进程。
- 连接来源时间线读取告警深度样本，并兼容从旧报告已有的逐连接 socket 行重建方向与进程归属。旧 Agent 没有上报归属字段的历史记录显示“未采集”，不再显示本机/外部/未知均为 0。
- 只有 conntrack 历史样本不足时，来源行为分析仍显示证据不足；单纯的连接数或 PID 归属不会被升级成恶意行为判断。

### v1.7.102：增加容器邮箱备注的精确查询 API

- 新增 `GET /api/v1/containers/user-note?host_id=…&runtime=…&project=…&container_name=…&container_id=…`，按完整容器实例身份精确读取用户邮箱与内部备注；返回 `found`、`user_email`、`user_note` 和 `updated_at`，容器重建后不会串到新实例。
- 邮箱及备注属于敏感管理信息，查询仅允许管理员和运维角色；只读角色返回 403。现有 `/api/v1/latest` 的授权字段行为保持一致。
- 前端 API 客户端新增 `getContainerUserNote(identity)` 调用封装。

### v1.7.101：修复定向处置的已消失目标误报

- 定向处置完成后重新扫描目标进程；若进程、服务和配置都没有清理变更，但完整回执证明目标已不存在且没有清理/信号错误，则作为幂等完成返回，界面明确显示“目标进程已不存在”，避免把过期告警反复显示为处置失败。
- Incus 容器内信号失败时，仅在宿主机命名空间回退精确匹配并终止了对应数量的目标、没有回退错误且复查剩余进程为 0 时，才认定处置成功；其他信号失败仍保留失败状态。
- Agent 回执增加匹配进程数、信号错误数和宿主机回退结果；服务器与告警页面按同一证明规则判定，不会只凭 `remaining_processes=0` 推断清理成功。

### v1.7.100：修复已有限速规则更新并强化自动限速网卡核验

- 更新已由 Agent 创建并确认归属的 tc 规则时，按原过滤器句柄和优先级原位修改；读回实际 policer 速率后才报告应用成功。新规则仍只选择空闲优先级，不触碰其他组件的规则。
- 自动阶梯限速增加 `/sys/class/net` 与 `/proc/net` 只读回退，兼容缺少 iproute2 JSON 输出的节点；保留底层采集错误，避免后续动作轮询把具体原因覆盖成通用提示。
- 带宽限速页继续按 Agent 最近一次内核读回值列出已生效的母机与容器上下行速率，并将失败方向单独标出。

一个轻量级的 **CS 架构多运行时容器监控工具**，可在同一宿主机同时采集 **Podman、Docker 和 Incus 容器**：

- **Server 主控端**：汇总多机容器状态、网络状态与预警，提供 Web 页面。
- **Client 宿主机 Agent**：以 systemd 服务方式运行在宿主机，按固定间隔采集数据并上报。
- **通信安全**：`HMAC-SHA256` 共享密钥签名鉴权。
- **面板登录保护**：Server 安装时随机生成 Web 用户名和密码，使用独立登录页与最长 12 小时的 HttpOnly 会话保护页面及管理 API；现有多用户与角色权限保持不变。
- **部署方式**：Server 容器化 + Client 宿主机 Agent，支持一键安装与一键更新。
- **多运行时发现**：默认 `auto` 自动发现全部已安装运行时，也可显式指定组合。

## 主要能力

### v1.7.99：修复带宽限速优先级冲突并显示实际生效值

- Agent 应用 `tc` policer 时先读取网卡过滤器优先级；默认优先级被占用时自动选择空闲优先级，遇到并发冲突会有限重试，不替换或删除其他组件的过滤器。
- 按确定性过滤器句柄读回和移除规则，兼容旧 Agent 保存的固定优先级规则；本地状态保存每个方向的优先级和最近确认的限速值。
- 带宽限速面板逐项显示 Agent 返回的失败原因，并列出最近一次内核读回确认的母机及容器上下行限额，明确区分已配置策略和已应用限速。
- 自动阶梯限速读取宿主机网卡清单失败时，回退到 `ip address show`；仍无法读取时在状态中显示底层命令诊断，便于定位采集差异。

### v1.7.97：重做母机防火墙选择并说明 Runman 不可用原因

- CN 协议复选不再受匹配方向限制；OpenVPN 始终可选择，并固定生成入站规则，其它协议按所选方向生成。
- 容器转发保护改为先选 Incus / Podman 和已采集网桥、再启用端口模板；不再只在勾选模板后才开放网卡选择，也不会悄悄自动全选网桥。
- 把 iperf3、常见矿池、BT/P2P 模板显示为固定目的端口匹配，并注明覆盖范围与随机端口限制，避免误以为会按应用或进程识别。
- Watcher Agent 上报 Runman 控制 socket 的具体探测结果（缺失、权限、拒绝、超时、旧 API 或 HTTP 异常）；全局策略把过期状态单列并跳过过期节点，避免把旧状态误报为当前可用。
- RFW 当前规则 API 没有逐条指定网卡的字段；CN 协议规则仍应用到该节点 RFW 实例的接口范围。逐条选择网卡需先扩展 Runman/RFW 接口，页面不会保存一个实际不会生效的网卡值。

### v1.7.95：按宿主机网卡峰值自动阶梯限速容器

- 在母鸡限速配置中选择网卡并填写上下行带宽后，可启用容器自动保护；Agent 仅对已确认经过所选网卡的 Incus / Podman 容器统计流量。
- 上下行分开计算。容器某方向的采样平均速率达到当前限额的 80%，累计有效采样窗口满 5 分钟后，按母机基准的 50%、25%、5% 阶梯限速，最低 1 Mbps；持续高占用时，每满 5 分钟再降一级。
- 低于当前容器限额的 50% 并累计 10 分钟后，每次恢复一级；恢复至无自动限速后继续观察。人工配置的容器限速仍与自动策略合并，取更严格的方向速率。
- 共享宿主机网络命名空间、无法读取网卡/命名空间、网络路径无法核实或流量采样不可用时，不启动新的自动限速；状态面板显示可映射数量、路径不匹配数量、采样不可用数量及当前触发限额。
- 使用 Agent 所有的 `clsact` policer filter；上行对应 `egress`、下行对应 `ingress`，超额数据包会丢弃，不替换 root qdisc，也不修改 RFW 规则。

### v1.7.94：升级回滚失败时仍保留失败回执

- Client 启动稳定性检查失败后，即使恢复旧版本也失败，更新器仍会写入明确的失败状态并保留回滚快照，避免更新结果缺失或被误判为已安装。

### v1.7.93：修复 Client 缺少 Incus 指标模块导致的上报中断

- Client 安装与托管升级会将 `incus_metrics.py` 安装到 Agent 使用的模块目录，并在升级前编译校验、纳入回滚快照。
- 托管升级等待 Client 进程连续稳定运行后再记录“已安装”；服务仍在崩溃重启时会触发回滚，避免把短暂启动误判为升级成功。

### v1.7.92：CPU 保护告警兼容性修正

- 在原有告警列表组装完成后追加 CPU 保护事件，避免改变现有告警类型和容器身份字段。
- 保持主机审计摘要与容器安全告警列表的既有边界。

### v1.7.91：持续高 CPU 的可恢复保护

- 对 Incus / Podman 容器使用运行时区间 CPU 计数和主机忙碌度核验；容器连续 10 分钟达到单核 CPU 用量 90% 或自身有效配额饱和 90%，且主机 CPU 忙碌达到 80% 后，才启动自动保护。IO wait 单独采集并排除在 CPU 忙碌率之外，避免把磁盘等待当成 CPU 繁忙。忽略进程启动以来的平均值，避免把累计平均误当成当前占用。
- 每台主机同时只限制一个 CPU 用量最高的容器；读取并保存原 CPU 配额后，将该容器临时限制到触发时实际 CPU 用量与原有效配额两者较低值的一半，操作后读回确认，确保新限额确实低于触发时用量。不会杀进程或停止容器。
- 告警记录触发时 1 秒 `/proc` 进程 CPU 增量采样（仅进程名、PID、CPU 百分比，不收集命令行参数）；即使进程归属未采到，也只根据可靠的容器运行时 CPU 计数保护。
- 容器 CPU 使用连续两次有效采样降到临时配额的 50% 以下后，恢复原 CPU 配置；遇到人工改动、无法读回或恢复失败时保留配置并告警，不覆盖人工设置。
- 将保护事件作为进行中告警通知用户，不归因为滥用；通知包含主机/容器 CPU、有效采样时长、进程采样和配额处理结果。关闭通用安全监控后不再启动新的限额，但已有临时限额仍会继续监测恢复并归还原设置。

### v1.7.90：修复离线主机详情与容器网桥识别

- 总览继续展示最近 7 天内未上报母机的最后一次容器样本，单独标注最后上报时间和离线时长；离线样本不计入在线 KPI、不触发实时告警或远程处置。
- 修复 Linux bridge 在 `ip address` JSON 中显示为 `ether` 时被误判为不可操作网卡的问题；Agent 以 Incus / Podman 明确报告的 bridge 网络与主机接口名匹配为准，并保留内核链路类型供诊断。
- Incus 网卡清单覆盖所有项目，并兼容不同版本 JSON 字段大小写；旧 Agent 已上报的可信运行时映射也可以正常显示。
- 启用固定端口策略时，自动把当前采集确认的 Incus / Podman 网桥加入可审阅草稿；管理员仍需检查并点击“保存并应用”才会下发，可按运行时或单网卡取消选择。
- 将离线主机及其最后样本的清理期限从 24 小时延长至 7 天，便于查找短期离线的节点；不会保留为在线或可操作状态。

### v1.7.89：回收过期升级动作并恢复分批发布

- 发布活动被标记为“已替代”后，将其仍处于排队或派发状态的升级动作标记为失效，释放全局并发槽位并解除同一节点的重复动作锁；仍处于人工控制状态的活动不会被改动。
- 修复连续升级活动遗留的旧动作占满 3 个并发槽位、导致新 canary 虽创建却不能继续派发的问题；回归测试覆盖多个旧动作占满槽位的情形。

### v1.7.88：修复托管升级动作回执丢失

- 托管升级通过 `systemd-run --no-block` 入队，让 Agent 立即回报“升级任务已启动”，不再等待 oneshot 更新脚本结束；启动器失败或超时会返回明确失败，不会中断 Agent 的动作处理循环。
- 修复灰度候选收到升级动作后心跳中断、服务端长期收不到升级结果，导致其他节点一直停留在旧版本的问题。

### v1.7.87：灰度升级恢复、带宽限速与 VMess 配置扫描

- 修复自动升级灰度节点离线后长期卡住的问题：新协调器会为过期灰度节点更换在线候选，仍要求新节点完成升级、健康检查和观察期后才继续全量发布。失败节点仍受重试次数和暂停规则约束。
- 总览母鸡卡片改为风险优先展开、匹配搜索时展开目标，并可单独打开主机/容器带宽限速。可选择采集到的在线网卡或 Incus/Podman 容器，设置上下行 Mbps；超限包会丢弃，不会修改已有 root qdisc 或 RFW 规则。
- 母鸡网络遥测先展示简短状态与峰值；网络信号、完整性审计、证据和修复建议按需展开。审计卡片横跨整行，减少长内容挤压。
- VMess 检测支持对启动参数明确指定的配置目录进行有上限扫描，并在待核实告警里说明具体进程、失败原因和已检查文件路径。配置扫描不完整时继续保持保护策略，不会据此扩大封锁。
- 防火墙页面说明 RFW 控制范围：它只管理已登记的 RFW 规则，不覆盖 UFW、宿主机 nftables/iptables、firewalld 或云安全组，也不表示宿主机全部防火墙状态已核验。

### v1.7.86：数据库增长监控、看板性能与发布校验

- Dashboard 改为按需加载；未打开的页面不下载，容器详情与 ECharts 分包，缩短首次进入看板时的加载路径。
- 运维中心新增 SQLite 主库、WAL 与可复用空间的增长趋势。采样按小时记录，最多保留 45 天；只有 24 小时增长同时超过绝对值和比例阈值时才提示运维人员，不向客户推送，也不会自动清理数据库。
- 发布流水线加入 Python 依赖审计、12 项浏览器回归、Linux 集成与容器镜像冒烟检查；FastAPI 更新至 `0.162.0`，`cryptography` 最低版本提高至 `50.0.2`。
- 抽离 Incus OpenMetrics 解析模块并保留原有调用接口；服务器镜像纳入数据库趋势采样模块，避免构建镜像缺少运行文件。

### 1.6.63：存储保留与自动处置

- 原始容器/主机采样默认保留 7 天（`RAW_RETENTION_SECONDS=604800`），并分别设 50,000 / 20,000 行的历史预算（`REPORT_MAX_ROWS` / `HOST_SECURITY_MAX_ROWS`）。达到行预算时优先淘汰旧采样，保留每个身份最新一条；大量不同身份可能使行数超过预算，预算不是硬性磁盘配额。历史图表可查询范围可能因此少于 7 天。告警终态、执行记录和取证默认保留 30 天（`PURGE_SECONDS`）；仍在处理的告警与放行策略保留。
- 清理按小事务批量推进，有积压时 5 秒后继续，错误写入日志；受登录保护的 `GET /api/v1/database/status` 返回文件页大小、空闲空间、WAL 大小及最近清理结果。新数据库默认增量回收。旧数据库 `auto_vacuum=0` 时，删除记录只产生可复用空闲页，不会缩小文件；不要删除运行中的 WAL/SHM 文件。
- 旧数据库迁移：停止 Server 后运行 `python /app/maintain_db.py /data/monitor.db --compact --server-stopped --backup /data/monitor.before-1.6.63.db`（镜像内可用）。工具先验证数据库，创建受限权限的 SQLite 一致性备份，再 `VACUUM` 并启用增量回收；要求至少数据库大小 3 倍的可用空间，拒绝覆盖已有备份。正常服务启动时不会自动执行昂贵的全库 VACUUM。备份包含管理数据，恢复也应停服；确认运行正常后再按自己的备份保留策略归档。
- `SECURITY_AUTO_REMEDIATE_SOCKS=true`：已确认空/弱密码的 SOCKS 进程默认自动停止，不需点击确认。只有认证已配置且未命中弱密码规则才解除持续处理。`SECURITY_AUTO_REMEDIATE_PANEL=true`：未被本地白名单放行、且有已配置程序特征证据的机场节点自动处置；成功/失败都会保留事件和通知，失败在后续采样重试。升级安装保留这两个开关。
- 处置复查精确程序名、服务身份及存活状态，不再仅凭历史 PID 或任意命令行子串杀进程；增加 SOCKS 的 OpenRC 服务关联停止，Incus 权限失败仍使用目标容器命名空间回退。复查发现残留或重启会报告失败。只有文件/名称猜测、未知认证、未识别的启动器或自定义改名程序，仍可能需要补充安全证据；Docker 继续保持仅提示/不自动处置，不能承诺任何容器与服务都能自动清理。

这些更改需 Server 与 Client 同时升级。旧 Client 对弱密码动作仍会拒绝；Server 放开按钮校验不等于节点已具备处理能力。


- **Podman / Incus 完整监测**：采集资源、网络、进程、监听端口、运行时暴露信息与安全风险。
- **Docker 默认仅提醒**：默认只发现 Docker 容器并展示信息提醒，不执行深度检查；可显式切换为完整监测或关闭发现。
- **节点侧安全检测**：针对 DDoS、CC、扫描、异常出站、可疑进程、危险容器配置和机场面板对接进行检测与预警。
- **NAT 场景识别**：不依赖 80/443 等固定端口，结合全部监听端口、运行时端口映射、进程、配置与面板域名判断。
- **OpenRC/Incus 清理兼容**：若非特权 Incus 容器内 UID 映射导致 `kill` 返回 `EPERM`，Agent 会从宿主机进入目标容器的 PID/挂载命名空间，重新核验精确进程名后终止进程；仍不会停止容器。
- **一键安装与更新**：`install.sh` 支持安装、更新和卸载；更新会复用 `/opt/narwhal-monitor/*.env` 配置并重建或重启服务。
- **告警快速处理**：活动告警可选择“禁止/持续拦截”“允许且不再提醒”或“本次取消提醒”；Podman/Incus 的机场面板对接告警支持定向清理，无认证 SOCKS 告警支持停止服务并持续拦截，Docker 不执行处理。
- **XMRig / XrayR 自动处置**：Podman/Incus 中精确命中的 XMRig 挖矿进程默认自动终止并清理明确的服务、配置和二进制；未获允许的 XrayR 节点后端默认自动定向清理。已加入域名白名单的合法 XrayR 不处理，Docker 仍只提醒。
- **告警历史与重新处置**：总览页可进入“告警历史”，按状态、级别、类型、主机和关键词筛选活动、已忽略、已处理及已恢复记录；可以对忽略记录重新禁止，也可以撤销“不再提醒”策略。
- **Telegram 告警机器人**：在“推送设置”中可保存多个 Bot Token 与 Chat ID/频道目标，并分别选择“仅严重告警”“警告及以上”或“全部告警”。Token 仅保存在 Server 数据库中，接口和页面始终只返回“已配置”状态。每个告警只保留一张动态状态卡，持续期间更新时长与次数，恢复后原消息会变成可追溯的“已恢复”历史卡片。
- **弱/空认证 SOCKS 自动处理**：Incus/Podman 中已确认弱密码或空密码的 SOCKS 服务默认自动停止；检测到非弱认证后解除持续策略。不会停止容器或删除 SOCKS 配置，OpenRC 服务可从启动级别移除。
- **按需深度上报**：可在容器详情页对可疑的 Podman/Incus 容器发起一次性深度采样，在下一 Client 周期查看瞬时流量、详细进程、连接 IP 及进程归属；Docker 默认仅提醒，不执行该任务。
- **Server-first 自动更新**：Server 与 Client 默认每 15 分钟检查 GitHub `main`；Client 必须通过共享密钥签名确认 Server 已运行目标版本才会升级，避免 Client 版本提前。更新只进行安全的 fast-forward 并记录日志。
- **统一版本状态**：仓库根目录 `VERSION` 是 Server 与 Client 的唯一版本源；每台主机显示“最新、版本不一致或版本未知”，安装摘要也会显示当前版本。
- **Server HTTPS 自动化**：支持自动拉起 Caddy 反向代理：
  - 域名场景：自动申请公网证书（ACME HTTP-01）。
  - Cloudflare 域名场景：支持 DNS Challenge（可橙云），自动签发并续期公网证书。
  - IP 场景：自动签发内部证书（`tls internal`），Client 使用共享密钥认证并自动获取、校验和保存公开根证书。

> 注意：IP 场景下的内部证书不是公网 CA 证书。Client 安装器会自动建立信任，但浏览器仍可能提示不受信任；如需浏览器直接显示“绿锁”，建议使用域名和公网证书。

## 部署、更新与卸载

### 主机身份、远程配置与删除

- Client 首次安装会生成不可变 `NODE_ID`，保存在 `/var/lib/narwhal-monitor/node-id`。面板中的 `HOST_ID` 只是显示名称；同一台机器重新安装、修改名称或纠正名称时，Server 会按 `NODE_ID` 合并历史，不会留下重复主机。
- 在“主机网络与安全遥测”表格可点击“配置”，下发主机名、上报/动作轮询间隔、容器运行时、Docker 监测模式和 Incus 项目。节点会在下一次动作轮询时原子写入并重启 Agent。
- 点击“删除”默认选择“远程卸载 Client”：节点会删除 Narwhal Client、配置、自动更新 timer 与 systemd 单元，不会停止或删除任何 Incus、Podman 或 Docker 业务容器。`NODE_ID` 会保留，以保证日后重新安装仍正确合并身份。旧版 Client 没有 `NODE_ID` 时需先升级；“只删除面板记录”会在节点下次上报后重新出现。

### 支持环境与部署方式

- 自动安装脚本面向 Debian / Ubuntu，依赖安装使用 `apt-get`，需要 root 权限。
- Server 部署为 Podman 容器；Client 部署为宿主机 systemd Agent。
- 推荐先在主控机部署一个 Server，再在每台客户节点部署 Client。Server 和 Client 可以安装在同一台机器，但生产环境通常分开部署。
- Client 节点应已安装需要监测的 Podman 或 Incus。若 Podman、Docker、Incus 均不存在，安装器会安装 Podman；安装器不会自动初始化 Incus。
- Server 与所有 Client 必须使用相同的 `SHARED_SECRET`。生产环境建议通过 HTTPS 上报，并妥善保存密钥。

### 首次部署

方式一：直接执行引导脚本。脚本会把仓库克隆到 `/opt/Narwhal-Cloud-podman-watcher`；目录已经存在时会同步到远端当前分支，再进入交互式安装器。若仓库有已跟踪或未跟踪的本地文件，脚本会先将它们保存到 Git stash，并显示恢复命令；若本地提交已与远端分叉，还会创建 `narwhal-bootstrap-backup-*` 备份分支。不会使用 `git clean`，因此被 Git 忽略的部署配置（如 `.env`）不会被删除。

```bash
curl -fsSL https://raw.githubusercontent.com/podcctv/Narwhal-Cloud-podman-watcher/main/scripts/bootstrap-install.sh \
  -o /tmp/narwhal-bootstrap-install.sh
sudo bash /tmp/narwhal-bootstrap-install.sh
```

安装器的固定选项菜单支持两种操作方式：使用键盘 `↑` / `↓` 移动并按回车确认，或直接输入选项数字（如 `1`、`2`、`3`）后回车；也可继续输入 `install`、`update`、`server` 等选项名称。Server 镜像来源、TLS 模式、Client Docker 策略等固定选项使用相同菜单。

方式二：手动克隆后安装。

```bash
git clone https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git
cd Narwhal-Cloud-podman-watcher
sudo bash scripts/install.sh
```

安装 Server 时依次选择：

1. 操作选择 `install`。
2. 目标选择 `server`；同机安装两端时选择 `both`。
3. “是否删除 Server 已有全部采集数据”首次安装可保持默认 `no`；已有数据时选择 `yes` 会清空数据库。
4. 记录共享密钥、访问地址和端口，以及安装摘要中随机生成的 `Dashboard Username` / `Dashboard Password`。镜像来源可选 `local` 本地构建，或 `github` 拉取镜像；拉取失败时会回退到本地构建。
5. 按需配置 Caddy HTTPS 与告警 Webhook。公网部署建议启用 HTTPS。

选择 `both` 时，Client 会从本机受保护的 Server 配置文件自动复用 `Client Server URL` 与共享密钥，不需要复制粘贴，也不会在进程参数中暴露密钥。Server 配置不完整时安装器会停止并明确报错，不会留下一个服务已启动但永远无法上报的 Client。

安装每台 Client 时依次选择：

1. 操作选择 `install`，目标选择 `client`。
2. `Server URL` 填写 Server 安装摘要中的 `Client Server URL`，例如 `https://monitor.example.com` 或 `https://10.0.0.2`。启用 Caddy 时不要追加随机 Backend Port；HTTPS 默认使用 443。
3. `Shared secret` 必须与 Server 完全一致；`Host ID` 必须在所有节点中唯一。
4. Client 会先使用系统 CA 验证 Server；如果是 IP/internal 模式，则通过 HMAC 认证接口获取公开根证书、验证响应签名并再次完成 TLS 校验。不会下载或传输 Caddy 根私钥。
5. 运行时建议保留 `auto`。Podman 与 Incus 默认完整监测；Docker 默认仅发现并提醒，不做深度扫描。新安装默认使用 `INCUS_PROJECT=all` 发现全部 Incus 项目；需要隔离时再填写一个精确项目名。
6. `Allowed airport panel domains` 填写允许对接的面板域名，多个域名用英文逗号分隔；留空表示不允许任何外部面板域名。

首次部署后的检查命令：

```bash
# Server 主控机
sudo podman ps --filter name=narwhal-monitor-server
sudo podman logs --tail 100 narwhal-monitor-server

# Client 节点
sudo systemctl status narwhal-monitor-client --no-pager
sudo journalctl -u narwhal-monitor-client -n 100 --no-pager
```

未启用 TLS 时，Server 监听安装时指定的 HTTP Backend Port。启用 Caddy 后，对外只使用配置的 HTTPS 地址，Backend Port 绑定到 `127.0.0.1` 供 Caddy 本机反代。Client 日志持续出现 `reported ... containers` 表示上报成功。

浏览器打开 Server 会进入 `/login` 独立登录页，不再显示浏览器原生认证弹窗。随机凭据只在首次安装摘要中显示，并保存在权限为 `0600` 的 Server 环境文件中；忘记时可在 Server 主机查看：

```bash
sudo awk -F= '$1=="DASHBOARD_USERNAME" || $1=="DASHBOARD_PASSWORD" {print $1"="substr($0,index($0,"=")+1)}' /opt/narwhal-monitor/server.env
```

登录后可从顶部「退出登录」注销。会话在 12 小时后、退出登录、账号禁用/密码更改或服务重启后失效；角色更改即时生效。浏览器不会在本地存储密码。请通过 HTTPS 访问，并保持后端仅监听回环地址，让 Caddy 终止 TLS 和设置转发头。旧脚本仍可主动发送 Basic 认证头访问管理 API，但服务不再返回 Basic challenge。Agent 签名认证与 Telegram 回调不受面板登录改动影响。

### 配置 Telegram 推送与推送内操作

进入面板顶栏的“推送设置”，添加 Telegram Bot Token 和目标 Chat ID（私聊/群组 ID）或频道用户名。点击“测试”会向目标发送一条测试消息，并在配置了公网回调地址时注册 Telegram 回调。

若需要从 Telegram 消息内直接操作，Server 必须可被 Telegram 以 HTTPS 访问。在 Server 的环境文件中增加实际的面板公网地址后更新 Server：

```bash
PUBLIC_BASE_URL=https://monitor.example.com
TELEGRAM_PROXY_URL=socks5h://代理地址:1080
```

不要在该变量中包含路径或结尾 `/`。系统为每个机器人生成独立、不可预测的回调路径；Bot Token 不会显示到浏览器、日志或 API 返回中。群组中请先让机器人收到一条消息，以便取得正确的 Chat ID。

### 更新现有部署

在之前克隆的仓库目录执行；如果首次使用的是其他目录，请替换下面的 `cd` 路径：

```bash
cd /opt/Narwhal-Cloud-podman-watcher
sudo bash scripts/install.sh
```

依次选择 `update`，再选择 `server`、`client` 或 `both`。更新流程会：

- 执行 `git fetch --all --prune` 和 `git pull --ff-only`，不会强制覆盖本地提交或冲突修改。
- 复用 `/opt/narwhal-monitor/server.env`、`server-install.env`、`client.env` 和 `client-install.env` 中的现有配置。
- 重新构建或拉取 Server 镜像并重建容器；更新 Client 代码和 Python 依赖后重启 systemd 服务。
- 默认保留 Server 历史数据库。脚本询问是否初始化数据库时必须选择 `no`；选择 `yes` 会永久清空历史采集和告警数据。
- 默认执行 Podman 未使用容器、镜像、卷、网络及 apt 无用依赖清理。宿主机同时承载其他业务时，建议使用下面的安全更新命令跳过全局清理：

```bash
sudo env SKIP_CLEANUP_ON_UPDATE=1 bash scripts/install.sh
```

也可以再次执行引导脚本，它会先更新 `/opt/Narwhal-Cloud-podman-watcher`，再打开相同的安装/更新菜单。

更新完成后，用首次部署后的检查命令确认 Server 与 Client 正常运行。若 `git pull --ff-only` 报错，请先处理仓库中的本地修改或分支分叉，不要使用会覆盖配置或代码的强制重置命令。

一键安装器中可选择 `诊断 Server（只读）`。该操作不重启、不删除也不修改容器，会集中显示更新单元、Podman 数据库、libpod scope、端口、HTTP 健康、脱敏配置及最近日志；也可直接运行：

```bash
sudo bash scripts/diagnose-server.sh
```

人工执行 Server 的 `install` 或 `update` 时，安装摘要会直接显示当前 `Dashboard Username` 和 `Dashboard Password`。systemd 后台自动更新会隐藏这些凭据，避免密码进入自动更新日志。

### 版本发布规则

Server 与 Client 必须使用同一个版本号。仓库根目录的 `VERSION` 是唯一版本源，安装器会把它写入两端环境配置，Client 每次上报也会携带自身版本。总览页每台主机的版本指示器含义如下：

- `vX.Y.Z · 最新`：Client 与当前 Server 版本一致。
- `Client vX.Y.Z · 应为 vA.B.C`：节点尚未更新到 Server 对应版本。
- `Client 版本未知`：旧版 Client 尚未携带版本；更新该节点并等待下一次上报即可。

以后每次功能或修复发布前都必须先提升语义化版本号，再提交代码：

```bash
bash scripts/bump-version.sh 1.0.1
git add VERSION
git commit -m "chore: release 1.0.1"
```

Server 镜像同时发布 `latest`、版本号和提交 SHA 标签；安装、更新摘要中的 `Version` 可用于部署审计。不要分别修改 Server 与 Client 版本。

### 重置 Server 面板密码

在一键安装器中选择独立操作 `reset-server-password`，或直接执行：

```bash
cd /opt/Narwhal-Cloud-podman-watcher
sudo bash scripts/install-server.sh reset-password
```

该操作保留现有 Dashboard 用户名，生成新的随机密码，并按现有配置重建 Server 容器使密码立即生效。共享密钥、TLS、数据库、告警历史和 Client 配置均不会重置。完成后终端会显示当前用户名和新密码。

### 自动更新

首次安装或手动更新后，安装器会为对应端启用 systemd timer：

- `narwhal-monitor-server-update.timer`
- `narwhal-monitor-client-update.timer`

Timer 每 15 分钟比较 GitHub `origin/main` 与已部署提交。自动更新具有以下保护：

- 仓库存在已跟踪的本地修改、分支分叉或不能 fast-forward 时拒绝更新，不会强制覆盖。
- Server 后端端口只接受 `1024-65535` 的纯数字；旧配置污染或旧容器删除后端口仍被占用时，会选择新的随机空闲端口并同步 Caddy/安装配置，不会终止宿主机上的 Podman、conmon、pasta 或其他业务进程。
- Server 镜像内的 `NARWHAL_VERSION` 必须与仓库 `VERSION` 一致，校验发生在删除当前 Server 容器之前；版本不一致时保留现有服务并等待正确镜像。
- Server 与 Caddy 使用事务式容器替换：旧容器先停止并改名为临时回滚副本，新容器运行及版本/TLS 校验成功后才删除副本；创建或启动失败会自动恢复上一版本，避免更新失败后长期出现 502。
- Server 使用 GHCR 镜像时，会核对镜像的提交 revision；新提交对应的多架构镜像未构建完成时保留现有容器，稍后重试。
- Server 同时核对状态文件、Git 提交与容器内 `NARWHAL_VERSION`；状态文件显示最新但容器仍为旧版时，会识别为 `deployment drift` 并重新部署。
- Server 手动安装与后台自动更新共用独占部署锁，防止两个流程同时替换容器。镜像准备完成后，旧容器会先改名暂存，新容器使用独立 cgroup 创建并接受版本、运行状态及真实 HTTP 检查；失败时恢复暂存容器，不依赖 `--replace` 覆盖正在运行的实例。
- Server TLS Proxy（Caddy）与主容器共用部署锁和事务替换流程；更新会保留 Caddy 数据卷中的证书，并同时回滚旧代理容器与旧 Caddyfile。
- 手工更新恰好与后台自动更新重叠时，安装器会明确显示部署锁等待原因，每 30 秒报告进度；后台流程结束后自动继续，最长等待 5 分钟，不再停在 `Already up to date.` 后看似无响应。
- 部署锁由独立的 `flock --close` 进程持有，安装脚本及 Podman/Caddy 子进程不会继承锁文件描述符；这避免了容器后台监控进程在安装结束后继续占锁。新版使用 `narwhal-monitor-server-deploy-v2.lock`，可直接避开旧版本已经泄漏的锁 inode。
- Client 更新前通过 HMAC 签名接口 `/api/v1/update/version` 核对 Server 的实际运行版本。Server 未升级、接口尚不可用或暂时无法连接时，Client 保持原版本并在下个 timer 周期自动重试。
- 首次人工安装 Client 时，若目标是尚无版本接口的旧 Server（旧版会返回 HTTP 401），安装器会明确警告并继续安装；这是为了避免新节点无法部署。后续自动更新仍执行严格的 Server-first 门禁。
- 更新成功才写入部署版本；失败会保留当前服务，并在下一周期重试。
- Timer 使用固定 15 分钟日历调度，并在安装器重写 unit 后主动重启。若旧节点显示 `active (elapsed)`、`Trigger: n/a` 或没有下一次触发时间，重新执行一次新版 Client/Server `update` 即可修复；新版不会再出现“Timer 看似启用但不再运行”的状态。
- 自动更新 systemd oneshot 的启动超时为 30 分钟，覆盖 GHCR 多架构镜像最长约 15 分钟的等待窗口；每个 Server/Caddy 会由唯一 transient scope 启动，payload 与 `conmon` 均位于独立的 `narwhal-monitor.slice`，不再继承 updater unit。更新单元使用 `Delegate=yes` 与 `KillMode=control-group`，可清理更新任务自身进程而不误杀容器，也不会因残留 `conmon` 导致下次启动报 `Device or resource busy`。容器退出后 scope 自动回收；若历史错误单元已经杀死 conmon，安装器会在确认 payload 已停止后清理孤儿元数据并继续重建。
- Server 更新不是只检查 Podman 的 `Running=true`：安装器还会校验镜像/运行时版本并实际访问回环后端 HTTP。Server 或 Caddy 任一步失败时，自动恢复上一版本容器和 Caddy 配置。
- Server 数据库使用 WAL 与 15 秒 busy timeout，节点写入和 Dashboard 读取可并行；历史清理使用 `reports(ts)` 索引、每批最多 5000 行且默认每 5 分钟至多执行一次，避免大库在每次上报/刷新时全表扫描并制造 IO 与锁竞争。
- 原有共享密钥、Dashboard 登录凭据、TLS 配置、数据库、Client CA 和节点域名白名单均保留。

查看自动更新状态和审计日志：

```bash
sudo systemctl list-timers 'narwhal-monitor-*-update.timer'
sudo journalctl -u narwhal-monitor-server-update.service -n 100 --no-pager
sudo journalctl -u narwhal-monitor-client-update.service -n 100 --no-pager
sudo tail -n 100 /opt/narwhal-monitor/server-auto-update.log
sudo tail -n 100 /opt/narwhal-monitor/client-auto-update.log
```

日志出现 `update deferred: waiting for Server to run the target version` 表示 Server-first 版本门禁正常生效，不是 Client 故障。若 Server 长时间没有升级，重点检查 `server-auto-update.log` 中的 `tracked local changes`、`GHCR image ... was not ready`、`deployment drift` 或 `deployment verification failed`。仅在灾难恢复且明确接受版本不一致时，才可人工设置 `NARWHAL_SKIP_SERVER_VERSION_GATE=1` 跳过 Client 门禁；不建议用于日常更新。

旧版本生成的更新单元如果执行 `systemctl start narwhal-monitor-server-update.service` 后显示 `timeout was exceeded` 或 `Device or resource busy`，说明旧 Server/Caddy 仍可能挂在 updater cgroup 下。不要直接把旧单元的 `KillMode` 改为 `control-group`，否则可能同时终止仍在提供服务的旧容器。请先从普通终端执行一次新版安装器，让容器迁移到独立 slice：

```bash
cd /opt/Narwhal-Cloud-podman-watcher
sudo git pull --ff-only
sudo env NARWHAL_AUTO_UPDATE=1 bash scripts/install-server.sh update
sudo systemctl reset-failed narwhal-monitor-server-update.service
sudo systemctl start narwhal-monitor-server-update.service
```

上述 `update` 会保留数据库、共享密钥、登录凭据和证书。完成后，`systemctl status` 的 updater cgroup 不应再包含 `conmon`、Server 或 Caddy 进程；若仍失败，执行 `sudo journalctl -u narwhal-monitor-server-update.service -n 150 --no-pager` 查看真正的后续错误。

如需暂停某一端自动更新，将对应配置中的 `AUTO_UPDATE_ENABLED=true` 改为 `false`：

```bash
sudo sed -i 's/^AUTO_UPDATE_ENABLED=.*/AUTO_UPDATE_ENABLED=false/' /opt/narwhal-monitor/client-auto-update.env
```

### 卸载

> **警告：卸载不可撤销。** 卸载器会停止并删除本项目 Server/Caddy 容器、Client systemd 服务、项目镜像，并递归删除 `/opt/narwhal-monitor`。该目录包含 Server SQLite 数据库、Client/Server 配置、共享密钥和 Agent 虚拟环境。需要保留历史时必须先备份。

备份示例：

```bash
sudo tar -C /opt -czf "/root/narwhal-monitor-backup-$(date +%F-%H%M%S).tar.gz" narwhal-monitor
```

执行卸载：

```bash
cd /opt/Narwhal-Cloud-podman-watcher
sudo bash scripts/install.sh
```

在菜单中选择 `uninstall`。卸载作用于当前宿主机上已经安装的本项目组件；Server 与各 Client 位于不同机器时，需要分别登录每台机器执行。卸载不会删除仓库目录、Podman/Incus/Docker 本身，也不会停止或删除客户的业务容器。

卸载后可验证：

```bash
sudo systemctl status narwhal-monitor-client --no-pager || true
sudo podman ps -a --filter name=narwhal-monitor
sudo test ! -e /opt/narwhal-monitor && echo "Narwhal data/config removed"
```

如确认不再需要源码，可在卸载完成后自行删除 `/opt/Narwhal-Cloud-podman-watcher`；安装器不会自动删除 Git 仓库。

### 仅操作单端

已在仓库目录内时，可直接调用单端安装器：

```bash
# 首次安装
sudo bash scripts/install-server.sh install
sudo bash scripts/install-client.sh install

# 更新并复用已有配置
sudo bash scripts/install-server.sh update
sudo bash scripts/install-client.sh update
```

直接运行单端 `update` 不会自动执行 `git pull`，请先自行更新仓库。完整卸载统一通过 `scripts/install.sh` 的 `uninstall` 菜单执行。

### 安装配置位置

| 内容 | 路径 |
| --- | --- |
| Server 运行配置 | `/opt/narwhal-monitor/server.env` |
| Server 安装参数 | `/opt/narwhal-monitor/server-install.env` |
| Server SQLite 数据 | `/opt/narwhal-monitor/server-data/monitor.db` |
| Server 导出的公开内部 CA | `/opt/narwhal-monitor/tls-ca/root.crt` |
| Client 运行配置 | `/opt/narwhal-monitor/client.env` |
| Client 自动获取的 Server CA | `/opt/narwhal-monitor/server-ca.crt` |
| Client 安装参数 | `/opt/narwhal-monitor/client-install.env` |
| Client Agent 与虚拟环境 | `/opt/narwhal-monitor/client-agent` |
| Client systemd 单元 | `/etc/systemd/system/narwhal-monitor-client.service` |
| 节点动态面板域名白名单 | `/opt/narwhal-monitor/panel-allowlist.json` |
| 已确认域名自动清理策略 | `/opt/narwhal-monitor/panel-auto-remediate.json` |
| 自动更新配置/版本/日志 | `/opt/narwhal-monitor/{server,client}-auto-update.{env,version,log}` |
| 自动更新 systemd timer | `/etc/systemd/system/narwhal-monitor-{server,client}-update.timer` |
| Caddy 配置与证书数据 | `/opt/narwhal-monitor/caddy` |

### 首次安装交互参数

Server 参数：

- 镜像来源（`local` / `github`）与 GitHub 镜像地址
- 后端监听端口、共享密钥、磁盘告警阈值
- HTTPS 反代开关、TLS Host、TLS Email 与证书模式（`auto` / `internal` / `cloudflare_dns`）
- Cloudflare API Token（选择 `cloudflare_dns` 时必填，需要 Zone DNS Edit 权限）
- 安全告警 Webhook URL 与最低告警级别

Client 参数：

- Server URL、共享密钥、唯一 Host ID 与上报间隔
- 容器运行时（`auto` 或 `podman,docker,incus` 的任意组合）
- Podman/Docker 镜像过滤规则、Incus 实例名/镜像过滤规则与项目名
- DDoS/CC/滥用/扫描监测开关、访问日志路径与机场面板域名白名单

Client 配置写入 `/opt/narwhal-monitor/client.env`：

```dotenv
SERVER_URL=https://monitor.example.com
SERVER_TLS_CA_FILE=
CONTAINER_RUNTIMES=auto
DOCKER_MONITOR_MODE=notice
MONITORED_IMAGE_PATTERNS=*
MONITORED_INCUS_PATTERNS=*
INCUS_PROJECT=all
```

`auto` 会发现主机上可用的 Podman、Docker、Incus。Podman 和 Incus 默认做完整采集，两个过滤项默认都是 `*`，所以其中的 Xboard、xboard-node、Nginx/Caddy、数据库及其他运行中容器都会进入监测；只有明确需要缩小范围时才改成镜像或实例名关键字。`INCUS_PROJECT=all` 使用一次 `incus list --all-projects` 发现所有项目，再按实例的真实项目采集，不会把同名实例混在一起；已有 Client 更新时保留原项目设置。Incus 虚拟机不在本项目的容器采集范围内。

Client 安装结束会执行一次只读、30 秒超时的 Incus 可见性检查，并显示当前项目范围内运行中容器数量。若精确项目为空但其他项目有容器，会提示改为 `all`。旧部署需要修复时可执行：

```bash
sudo sed -i 's/^INCUS_PROJECT=.*/INCUS_PROJECT=all/' /opt/narwhal-monitor/client.env
sudo systemctl restart narwhal-monitor-client.service
```

Docker 默认采用 `notice`：只枚举容器、执行一次轻量 `df` 获取容器根盘容量，并在仪表盘产生信息提醒；不执行 stats、进程/连接/日志读取、镜像层尺寸计算或安全判断。可改为 `full` 启用与 Podman 相同的完整监测，或改为 `off` 完全忽略。信息级 Docker 提醒默认不会触发 `warning` 级别的 Webhook；需要推送时把 Server 的 `ALERT_WEBHOOK_MIN_SEVERITY` 改为 `info`。

Incus 的 CPU 与网络速度由累计指标的相邻采样差值计算，因此 Agent 启动后的第一次上报可能暂时为 0；从第二次采样起会得到区间值。内存、连接数、磁盘和进程信息仍会在首次采样采集。

## DDoS / CC / 滥用 / 扫描监测与预警

所有安全监测都在节点宿主机执行，不会向远端 Xboard 发起额外探测。Agent 会对 Podman 和 Incus 容器执行完整采集，无论其中运行的是 Xboard 面板、xboard-node、协议服务、反向代理还是其他组件，都会检查其网络命名空间、连接、进程和配置线索。Docker 默认仅枚举、轻量读取根盘容量并提醒，不读取日志且不做安全判断；只有将 `DOCKER_MONITOR_MODE=full` 后才执行同类深度采集。

安全监测默认启用，作用是**发现并告警**，不会自动封禁 IP 或修改防火墙：

- **流量型 DDoS**：容器入站 B/s、入站 pps 超阈值。
- **SYN Flood**：容器网络命名空间中 `SYN_RECV` 数量超阈值。
- **入站 IP 扇出**：容器当前入站去重 IP 大于 10 时重点告警，并在容器详情中展示对应通信进程、PID、本地/远端端点和方向。
- **SOCKS 滥用与弱认证**：识别 MicroSocks、Dante/sockd、3proxy、GOST、Xray/V2Ray、sing-box 等 SOCKS 服务。发现无认证、短密码或常见弱密码时告警，但绝不上报用户名和密码；SOCKS 入站 IP 大于通用阈值时将通用告警替换为一条 SOCKS 专项告警，避免重复提醒。
- **HTTP/CC**：Nginx combined 或 Caddy JSON 访问日志中的总 RPS、单 IP RPS、4xx 比例超阈值。
- **扫描**：同一来源在采样时刻同时触达的本地端口数超阈值，或访问日志命中敏感 Web 路径探测规则。
- **滥用**：容器出站连接外部 IP 扇出过大、SMTP/Telnet/SMB/IRC 等敏感端口连接过多，或单 IP 产生大量 401/403/429。
- **疑似恶意程序**：Podman/Incus 容器进程命令命中可配置的高风险挖矿木马、僵尸网络或入侵工具特征。
- **连接行为**：主动 TCP 建连速率、TCP 连接失败速率和 UDP 出站数据报速率异常，辅助发现端口扫描、撞库代理、反射流量与僵尸网络活动。
- **出站流量**：TX B/s 和 TX pps 超阈值，辅助发现代理滥用、数据外传和对外攻击。
- **隔离配置审计**：Podman privileged、高风险 capabilities、宿主机命名空间/敏感目录挂载，以及 Incus `security.privileged`、`security.nesting`、`raw.*` 和宿主机设备暴露。
- **进程风暴**：通过容器 cgroup 的 `pids.current` 检测进程数异常，辅助发现 fork bomb、批量任务和失控脚本。
- **机场面板对接**：识别 Xboard-Node、XrayR、V2bX、Soga 等节点程序，以及 `ApiHost/ApiKey/NodeID`、`panel.url/token/node_id` 等配置特征；只上报面板域名和命中特征，不上报 API Key、Token 或配置正文。

Client 默认阈值位于 `/opt/narwhal-monitor/client.env`：

```dotenv
SECURITY_MONITOR_ENABLED=true
SECURITY_ACCESS_LOG_PATHS=/var/log/nginx/access.log,/var/log/caddy/access.log
SECURITY_CONTAINER_ACCESS_LOG_PATHS=/var/log/nginx/access.log,/var/log/caddy/access.log
SECURITY_ACCESS_LOG_MAX_BYTES=1048576
SECURITY_SOCKET_SNAPSHOT_MAX=500
SECURITY_COMMUNICATION_DETAIL_MAX=100
SECURITY_CONNTRACK_SNAPSHOT_MAX=5000
SECURITY_HOST_PROXY_SOCKET_MAX=5000
RUNTIME_COMMAND_TIMEOUT_SECONDS=30
SECURITY_PANEL_ENV_SCAN_MAX_PROCESSES=32
SECURITY_PANEL_ENV_MAX_BYTES=16384
GEOIP_MMDB_PATH=/usr/share/GeoIP/GeoLite2-Country.mmdb
GEOIP_HTTPS_ENABLED=true
GEOIP_HTTPS_ENDPOINT=https://api.country.is/
GEOIP_DETAIL_ENDPOINT=https://ipwho.is/{ip}
GEOIP_CACHE_MAX_ENTRIES=4096
GEOIP_CACHE_TTL_SECONDS=86400
GEOIP_NEGATIVE_CACHE_TTL_SECONDS=900

ALERT_DDOS_RX_BPS=100000000
ALERT_DDOS_RX_PPS=50000
ALERT_DDOS_SYN_RECV=200
ALERT_CONN_WARNING_THRESHOLD=500
ALERT_CONN_CRITICAL_THRESHOLD=1000
ALERT_INBOUND_UNIQUE_IPS=10
ALERT_CC_TOTAL_RPS=100
ALERT_CC_IP_RPS=30
ALERT_CC_4XX_RATE=0.5
ALERT_CC_MIN_REQUESTS=50
ALERT_SCAN_UNIQUE_PORTS=20
ALERT_ABUSE_OUTBOUND_UNIQUE_IPS=200
ALERT_ABUSE_SUSPICIOUS_CONNECTIONS=20
ALERT_ABUSE_TX_BPS=100000000
ALERT_ABUSE_TX_PPS=50000
ALERT_ABUSE_TCP_OPENS_PER_SEC=200
ALERT_ABUSE_TCP_FAILS_PER_SEC=50
ALERT_ABUSE_UDP_OUT_PER_SEC=10000
ALERT_ABUSE_PROCESS_COUNT=500
SECURITY_CONFIG_AUDIT_ENABLED=true
SECURITY_SUSPICIOUS_OUTBOUND_PORTS=25,465,587,23,445,6667
SECURITY_WEB_SCAN_PATTERNS=.env,.git,wp-login,wp-admin,phpmyadmin,actuator,server-status,cgi-bin,vendor/phpunit,etc/passwd,boaform,hnap1
SECURITY_SUSPICIOUS_PROCESS_PATTERNS=xmrig,kinsing,kdevtmpfsi,watchbog,cryptonight,minerd,pwnrig,teamtnt,stratum+tcp,stratum+ssl,/dev/tcp/,nc -e,ncat -e,socat exec:,mkfifo /tmp
SECURITY_AUTO_REMEDIATE_XMRIG=true
SECURITY_AUTO_REMEDIATE_XRAYR=true
SECURITY_PANEL_PAIRING_DETECTION_ENABLED=true
SECURITY_ALLOWED_PANEL_DOMAINS=
SECURITY_PANEL_ALLOWLIST_FILE=/opt/narwhal-monitor/panel-allowlist.json
SECURITY_PANEL_AUTO_REMEDIATE_FILE=/opt/narwhal-monitor/panel-auto-remediate.json
SECURITY_PANEL_PROCESS_PATTERNS=xboard-node,xrayr,v2bx,soga,sspanel-uim-node
SECURITY_PANEL_CONFIG_PATHS=/etc/XrayR/config.yml,/etc/V2bX/config.json,/etc/V2bX/config.json.bak,/usr/local/V2bX/config.json,/usr/local/V2bX/config.json.bak,/etc/xboard-node/config.yml,/etc/xboard-node/config.yaml,/usr/local/etc/bby-agent.yml,/opt/xboard-node/config.yml,/app/config/config.yml,/etc/soga/soga.conf,/etc/soga/config.yml
SECURITY_SOCKS_CONFIG_PATHS=/etc/danted.conf,/etc/sockd.conf,/etc/3proxy/3proxy.cfg,/etc/3proxy.cfg,/etc/xray/config.json,/usr/local/etc/xray/config.json,/etc/v2ray/config.json,/usr/local/etc/v2ray/config.json,/etc/sing-box/config.json,/etc/sing-box.json,/etc/gost/config.yaml,/etc/gost/config.json
SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE=/opt/narwhal-monitor/socks-auth-enforcement.json
ACTION_POLL_INTERVAL=10
ALERT_WEB_SCAN_REQUESTS=10
ALERT_AUTH_FAILURES_PER_IP=20
```

为避免异常容器拖住整台节点，所有只读运行时采集命令默认最多执行
`RUNTIME_COMMAND_TIMEOUT_SECONDS=30` 秒，超时后跳过该项并继续其他容器。机场特征的
环境变量检查优先读取已经命中的进程，并将每个容器的环境扫描限制为最多 32 个进程、
每个进程最多 16 KiB；每个 `/proc/<pid>/environ` 只读取一次，不会递归扫描容器文件系统。

连接来源国家解析优先使用 `GEOIP_MMDB_PATH` 指定的本机 GeoLite2 Country MMDB；数据库
不存在或没有对应记录时，才把最多 100 个公网 IP 通过一次 HTTPS 批量请求发送到
`GEOIP_HTTPS_ENDPOINT`。按需深度取证还会通过 HTTPS `GEOIP_DETAIL_ENDPOINT` 补充地区、
城市、运营商和 ASN。私网 IP 不会发送到外部服务，也不会显示为公网客户端或公网出站目标。结果使用有大小上限和过期时间的
内存缓存。对隐私要求更高时可设置 `GEOIP_HTTPS_ENABLED=false`，此时没有本地 MMDB 的
地址统一显示为 `UN`。GeoLite2 数据库需要按
[MaxMind 官方说明](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)自行获取和更新；
默认 HTTPS 回退接口为可自托管的 [country.is](https://github.com/lineofflight/country)。

连接数严格大于 `500` 时产生 warning，严格大于 `1000` 时升级为 critical。Server 会独立记录每个容器的连续超限窗口；连接数严格大于 `1500` 且连续满 1 小时后，才经 HMAC 签名动作通道自动停止整个容器（调用对应运行时的 `stop`），不是终止容器内某个进程。连接数恢复到阈值以内会清除连续超限状态；若相邻超限样本间隔超过 600 秒，连续计时也会重新开始，因此偶发的短时高峰不会触发处置。该告警不提供人工“定向处置”按钮，避免把整容器停止误解为进程清理；人工定向处置仅用于机场面板、SOCKS 和恶意进程等有明确安全目标的告警。

Agent 会同时读取宿主机 `SECURITY_ACCESS_LOG_PATHS`，并通过对应的 Podman/Docker/Incus 运行时进入每个容器读取 `SECURITY_CONTAINER_ACCESS_LOG_PATHS`。因此面板或反代日志既可以位于宿主机，也可以只存在于容器内部；文件不存在的容器会自动跳过。也可以把容器日志只读挂载到宿主机后，仅保留宿主机路径。日志不可读时网络层检测仍正常运行，但该容器不会产生 HTTP/CC 日志告警。

`SECURITY_ALLOWED_PANEL_DOMAINS` 是允许对接的面板域名白名单，支持父域匹配，例如配置 `example.com` 会允许 `panel.example.com`，但不会允许 `example.com.evil.test`。默认留空表示没有允许的第三方面板；发现明确面板域名时产生 critical 告警，只发现节点程序或配置特征但无法提取域名时产生 warning。检测过程不会把配置文件正文、API Key 或 Token 写入上报数据。

SOCKS 检测复用本轮已经读取的容器进程列表；只有发现 SOCKS 候选进程或容器身份特征时，才对 `SECURITY_SOCKS_CONFIG_PATHS` 中最多 30 个精确路径各读取前 256 KiB 并在容器内返回风险标记，不传输配置正文或凭据。无认证/弱密码且确认存在公网或 NAT 暴露时为 critical，未确认公网暴露时为 warning。弱密码判断包含常见默认密码和少于 8 位的命令行密码。

对于已确认 `no_auth` 或 `weak_password` 的 Incus/Podman SOCKS 服务，Client 默认自动处理，无需手工确认；面板仍可手动重试“停止并持续拦截”。处置限定到本次风险进程及其关联 systemd/OpenRC 服务，保留配置文件和容器；OpenRC 的自动启动关联可被移除。手工持续策略按运行时、项目与容器名称保存于 `SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE`。仅 `configured` 会解除策略，`weak_password` 不再作为放行条件。存活复查失败会记录残留，后续采样继续处理；Docker 始终仅提示。

### Critical 机场对接、挖矿与 SOCKS 告警的处理

活动告警在总览页提供三个处置入口：

- **禁止**：只出现在证据完整的 Podman/Incus `unauthorized_panel_pairing` 告警上。Server 把经过 HMAC 签名的定向动作发送给对应节点。Agent 不停止或删除容器，只在目标容器内部终止本次检测命中的机场节点进程，停用并删除对应 systemd/OpenRC 服务定义，并删除本次检测到且同时属于 `SECURITY_PANEL_CONFIG_PATHS` 的配置文件。PID 在上报后被守护器重启也不会阻断清理：Agent 会重新扫描当前精确进程身份，并从 cgroup 反查 `bby-agent` 这类与程序不同名的真实服务。Agent 会再次校验容器、运行时、进程特征和配置路径，不接受任意 Shell 或任意文件路径。首次人工清理成功后，本次命中的具体面板域名会写入节点侧 `SECURITY_PANEL_AUTO_REMEDIATE_FILE`；同一域名以后再次出现时会自动执行清理且不再向 Server 提醒，新域名仍正常告警。
- **XMRig 自动清理**：XMRig 是加密货币挖矿程序。Podman/Incus 中只有进程名、`argv[0]` 或可执行文件 basename 精确等于 `xmrig` 时才自动处理；处理范围限于 XMRig 进程、同名 systemd/OpenRC 服务以及内置的精确配置/二进制路径，不做模糊文件搜索，不停止容器。其他可疑进程特征只告警，不自动删除。
- **XrayR 自动清理**：XrayR 是支持多种机场面板的代理节点后端，本身不等同于恶意软件。只有节点侧检测到 XrayR 且面板未被域名白名单明确允许时才自动定向清理；在“允许且不再提醒”中放行对应域名后不会处理。撤销忽略时，Server 会同步从节点动态白名单删除该精确域名。
- **允许且不再提醒**：永久抑制该告警指纹。机场面板告警按具体域名形成指纹，并把域名写入节点的 `SECURITY_PANEL_ALLOWLIST_FILE`；其他告警按主机、运行时、项目、容器和类型抑制。更新 Client/Server 后策略保留。
- **本次取消提醒**：只隐藏当前连续出现的这一次事件。只要节点后续一次上报不再包含它，事件即恢复；以后再次出现会重新展示并通知。

按钮决策记录在 `security_alert_decisions`，永久抑制策略记录在 `security_alert_policies`，节点动作记录在 `security_actions`。页面会显示“等待节点 / 节点处理中 / 已完成 / 失败”及结果。动作响应由共享密钥签名校验，即使使用 internal CA，也不会接受被篡改的动作。Docker 仍没有“禁止”，但可以选择永久不再提醒或取消本次提醒。

总览右上角“告警历史”进入 `/alerts/history`。历史页保留 `active`（活动）、`suppressed`（允许且不再提醒）、`dismissed`（本次取消提醒）、`remediated`（已处理）和 `resolved`（已恢复）记录，并展示最近人工决定、节点动作结果及自动处置结果。对已忽略记录点击“重新禁止/处理”会先撤销 Server 抑制策略，再下发新的定向动作；点击“恢复提醒”只撤销忽略策略，机场面板告警还会同步撤销节点域名白名单。

进程告警会上报命中的 PID；Agent 清理前会再次校验 PID、进程状态和允许的程序特征，并忽略僵尸进程。只有实际终止进程或删除服务/配置后才算“禁止成功”，随后活动告警立即转为已处理；如果清理数全部为 0，动作显示失败并提供“重试禁止”，不会再把零清理误报为完成。若后续采样再次发现同一特征，按钮会明确显示“再次禁止”。

> 机场组件“禁止”会删除容器内对应配置与服务定义，属于不可逆操作，页面提交前会列出目标及后续自动清理规则并要求二次确认；它不删除机场程序二进制。XMRig 精确处置会额外删除内置白名单中的 XMRig 二进制路径。两类处置都不会停止 Incus/Podman 容器。需要取消某个域名的自动清理时，可在历史页选择放行，或从节点的 `/opt/narwhal-monitor/panel-auto-remediate.json` 中删除该域名并保持 JSON 格式有效。

### 容量采集与容器详情

- 总览页的“容器状态”按主机分组，默认全部折叠；点击主机栏展开容器卡片，15 秒自动刷新时会保留当前展开状态。主机栏集中展示运行时数量、在线状态、IPv4/IPv6、主盘容量和最近上报时间。
- 展开后的容器使用响应式卡片展示 CPU、内存、连接、进程、RX/TX、容器根盘、端口/NAT、来源国家和安全检查；宽屏自动分栏，窄屏自动换行，不再依赖超宽表格或浏览器横向滚动条。
- Incus CPU、内存和网络统一来自每轮一次的 `/1.0/metrics` 容器级快照；内存已用量按 `MemTotal - MemAvailable` 计算，不再把 `MemTotal` 误当已用量而显示为 100%。同一轮所有 Incus 容器复用快照，避免按容器重复读取指标。
- “容器根盘(/ 总量/可用)”来自容器内 `df -P /`，表示容器看到的根文件系统容量，不是镜像层大小。
- “宿主机主盘”优先读取 `/data`；节点没有 `/data` 时自动回退到 `/`，页面同时显示实际挂载点，不再把不存在的 `/data` 显示为 `0 B / 0 B`。
- 主机 IPv4/IPv6 指示器先用宿主机路由做无数据包探测，再按需使用容器网络探测，不再因容器没有安装 `curl` 或 `ip.sb` 不可达而把正常宿主机误报为异常。
- 主机遥测使用无横向滚动的自适应指标卡片，HTTP 按宿主机/容器日志来源分别展示请求数、RPS、单 IP RPS、去重 IP 和 4xx/5xx 比例，避免跨来源重复计算反代请求。未配置、文件缺失、权限问题和解析失败会明确展示，未采集不会伪装为 0。请将真实 Nginx/Caddy access log 路径加入 `SECURITY_ACCESS_LOG_PATHS`（宿主机）或 `SECURITY_CONTAINER_ACCESS_LOG_PATHS`（容器内）；需同时更新 Server 和 Client 才能获得分来源数据，首次读取从文件末尾开始，下一采样周期才产生增量统计。普通 JSON 应用日志不会作为 HTTP 请求计数。
- DDoS/HTTP 卡片颜色取自本次采样对应类型的实际事件（正常绿色、警告黄色、危险红色，未采集/过期灰色），不会把 Docker 发现等普通提示算成 DDoS 告警。展开“本次采样事件”可查看容器、类型、原因、触发值和阈值；该列表是采样证据，放行/处置/历史推送状态仍以告警历史为准。
- 今日峰值采用 UTC+8，单容器最高连接/入站/出站 IP 是各容器采样最大值，另列全容器合计连接峰值；不是全天累计 IP 去重，也不表示所有峰值同时发生。网络流量是受监控容器汇总，并非物理网卡整机流量。推送按触发时的单容器值判断，因此不能直接与合计峰值比较。

遥测阈值是可配置的运维起点，不是适用于所有业务的公认攻击标准。容量、服务用途、采样窗口和正常流量基线不同，阈值也应不同；高请求量或 5xx 本身不能证明受到攻击。检测沿用节点 `ALERT_*` 配置，并随采样上报实际阈值供页面显示，配置修改后需重启 Client。

| 指标 | 默认警告 | 默认危险 | 节点环境变量 |
| --- | --- | --- | --- |
| 单容器连接数 | >500 | >1000 | `ALERT_CONN_WARNING_THRESHOLD` / `ALERT_CONN_CRITICAL_THRESHOLD` |
| 单容器入站 IP | >10 | >20 | `ALERT_INBOUND_UNIQUE_IPS`（危险为 2 倍；小型代理审计的敏感默认值，公共网站应按基线调高） |
| 入站包速率 | ≥50,000 pps | ≥100,000 pps | `ALERT_DDOS_RX_PPS` |
| SYN_RECV | ≥200 | ≥400 | `ALERT_DDOS_SYN_RECV` |
| HTTP 总请求 | ≥100 rps | ≥200 rps | `ALERT_CC_TOTAL_RPS` |
| 单 IP 请求 | ≥30 rps | ≥60 rps | `ALERT_CC_IP_RPS` |
| 4xx 比例 | ≥50% | ≥100% | `ALERT_CC_4XX_RATE` |
| 5xx 比例 | ≥5% | ≥10% | `ALERT_HTTP_5XX_RATE` |

HTTP 错误比例至少需要 `ALERT_CC_MIN_REQUESTS=50` 次请求。速率是采样周期平均值，短时尖峰可能被平滑；本次改动不新增持续抓包或主动扫描。监控原则参考 [Google SRE 的流量、错误与饱和度监控说明](https://sre.google/sre-book/monitoring-distributed-systems/)，表中数值为项目默认值，非该文档给出的统一标准。

- 入站去重 IP 优先通过宿主机 conntrack 与端口映射还原真实公网来源，兼容 Incus proxy、`incus network forward`、宿主机 iptables/nftables DNAT、唯一 PID 用户态转发和 Podman 端口映射；`10.x` 等代理网关地址不会冒充公网来源，不可还原时明确回退到容器网络命名空间的 `/proc/net`。默认只有数量大于 `ALERT_INBOUND_UNIQUE_IPS=10` 才产生重点告警。每轮最多读取 5000 条 conntrack 和 5000 条宿主机代理 socket 记录，Incus 网络转发配置每 4 分钟最多读取一次，并通过一次最多 500 条的容器 `ss` 快照把目标端口归属到通信进程，默认最多上报 100 条活动连接；全程不抓包、不扫描文件，不持续占用 CPU。同一代理 PID 对应多个容器目标时不会猜测归属，避免误告警。
- Incus/Podman 容器首次产生“连接数过高”事件时，Server 会自动下发一次有界深度取证任务，同一轮异常不会重复排队。Agent 在下一次上报中将公网连接明确拆分为“接入容器的客户端 IP”和“容器主动访问的目标 IP”，采集方向、关联进程、国家/地区、城市、运营商与 ASN；网桥、NAT 和代理使用的私网地址（例如 `10.91.0.1`）不会作为公网目标展示。发起方向优先用 conntrack 原始/回包五元组确认，并关联 socket 的 PID/进程；TCP SYN 状态可直接确认握手发起方。没有这些证据时，已建立 TCP 或 UDP 连接只标为“推定/未知”，不会据此断言恶意或归责客户。采集不包含数据包正文、账号或业务载荷。完整证据与采集时间绑定到告警历史，Telegram 动态告警卡同步显示双向摘要。告警恢复后证据仍按 Server 历史保留周期保存。
- 宿主机磁盘结果缓存 30 秒，同一轮多个容器复用；容器侧只读取文件系统元数据，不遍历目录、不计算目录大小。镜像层 `inspect --size` 默认关闭；确需采集时可在 Client 环境中设置 `CONTAINER_LAYER_SIZE_ENABLED=true`，但这可能增加 IO。
- 统计页的 Top10、“全部容器”和总览容器卡片均跳转到独立的容器详情页，不再借用首页弹窗。详情展示容器内部 CPU/内存/连接/进程/网络命名空间、历史速率曲线、监听端口、NAT/代理映射、通信进程与端点、文件系统和配置风险；页面刷新只复用既有上报，不额外触发节点采集。
- 怀疑某个容器时，可在详情页点击“请求深度上报”。Server 会排入经过现有 HMAC 通道下发的一次性任务；Client 通常在 10 秒内领取，并立即进入下一上报周期，只对目标容器采集约 1 秒的瞬时 RX/TX 与 pps、最多 100 条进程、最多 250 条连接、连接 IP 及进程归属。上报失败会保留任务重试，上报成功即清除任务并恢复普通轻量采集。该能力不进行持续抓包、不读取业务文件，进程命令行中的常见密码、令牌和 API Key 参数会先脱敏。
- 极简容器没有安装 `ps` 或 `ss` 时，按需深度上报会只读宿主机 `/proc`，按目标容器 init PID 的进程树和 socket inode 做有界回退归属；最多扫描 20000 个宿主机 PID、10000 个目标进程文件描述符和 2000 条目标网络命名空间 socket 记录。该回退只在人工请求时执行，不增加普通周期的持续 IO/CPU 压力。
- 详情页会显示“已排队、节点已领取、报告已收到或失败”的明确状态。任务处于等待状态时按钮不可重复提交；历史深度报告随普通报告保留周期保存，可作为当时的排查快照，但不代表持续实时状态。
- 历史图表与统计聚合默认只使用当前 Client 版本产生的样本，避免升级前后的指标口径混在同一曲线或平均值中；旧数据仍保留在数据库，不执行破坏性清理。

机场面板/节点识别**不假设 80、443 或任何固定端口**。Agent 会枚举容器网络命名空间中的全部 TCP 监听端口，并展示 Podman publish 以及 Incus proxy device 中可见的外部端口到内部端口映射；公网 NAT 端口与容器端口可以完全不同。由宿主机自定义 nftables/iptables、上游路由器或云厂商实现且没有运行时元数据的 DNAT 无法可靠归属到具体容器，此时仍通过进程、配置文件、环境变量和面板域名判断是否存在机场对接。
Agent 启动时会把现有日志位置记为基线，只统计之后追加的新请求，避免把历史日志误判为当前攻击。
如果面板经过 Cloudflare/CDN/上游代理，请先在 Caddy 配置 `trusted_proxies`，或在 Nginx 配置 real IP 模块并让日志记录真实客户端地址；否则“单 IP CC”看到的可能只是代理节点地址。

Server 的 `/opt/narwhal-monitor/server.env` 可配置：

```dotenv
ALERT_WEBHOOK_URL=https://example.com/your-webhook
ALERT_WEBHOOK_MIN_SEVERITY=warning
ALERT_CONN_WARNING_THRESHOLD=500
ALERT_CONN_CRITICAL_THRESHOLD=1000
CONNECTION_STOP_THRESHOLD=1500
CONNECTION_STOP_DURATION_SECONDS=3600
CONNECTION_STOP_MAX_GAP_SECONDS=600
OFFLINE_HOST_PURGE_SECONDS=604800
DASHBOARD_USERNAME=安装时随机生成
DASHBOARD_PASSWORD=安装时随机生成
```

Webhook 仅在告警首次出现、级别升级或恢复后再次出现时发送，正文格式为：

```json
{"event":"narwhal.security_alert","alert":{"host_id":"host-1","type":"ddos_packets","severity":"warning","message":"..."}}
```

Telegram 机器人保存时会立即向目标发送一条配置验证消息，并在已配置 `PUBLIC_BASE_URL` 时自动注册告警卡片的操作回调；Token、Chat ID 或频道权限无效会直接返回 Telegram 的具体错误，不会静默保存。机器人列表会显示最近一次发送成功时间或失败原因。告警正文会按 Telegram HTML 规则转义，进程参数和比较符号不会再导致整条消息被拒绝。

每个达到推送级别的告警只发送一条动态状态卡。告警持续期间，Server 最多每分钟编辑一次原消息，更新持续时间、出现次数、级别和最新说明，不会反复发送新消息；告警消失、被忽略、静默或自动处置时立即编辑同一条消息。自然恢复会显示“已恢复，持续 N 分钟”，并作为历史消息保留；已经恢复且从未推送过的低级别告警不会补发。保存机器人后，当前仍活动且达到推送级别的告警会在下一次节点上报时建立状态卡。

连接数过高告警的自动深度取证完成后，同一张 Telegram 卡会分别追加公网客户端和公网出站目标，并显示国家/地区、城市与运营商。网页“安全告警历史”中的该告警可展开完整证据，查看最多 100 个公网 IP 的连接数、方向、归属地、运营商、ASN 和关联进程。

机器人支持按钮驱动的交互式告警控制台。在目标聊天中发送 `/menu` 可打开主菜单，发送 `/alerts` 可直接进入活动告警列表；后续无需输入参数，可通过按钮查看全部/严重/警告告警、分页、查看详情、刷新和返回。告警详情提供“本次忽略”“标记已处理”“永久不再提醒”，安全证据充分的机场面板、无认证 SOCKS 和精确 XMRig 告警还会显示“定向处置”。所有改变状态或下发动作的操作都先进入说明明确的二次确认页。机器人只接受来自配置目标 Chat ID（或目标 `@频道`）的交互，其他聊天不会获得告警数据。

配置了公网 `PUBLIC_BASE_URL` 时交互通过 Telegram Webhook 接收；未配置时 Server 自动使用 `getUpdates` 轮询，不需要开放额外端口。两种模式都会注册 Telegram 命令菜单。主动推送的告警卡片使用“查看并处理”进入同一套引导流程，旧版消息中的操作按钮仍兼容。

Telegram 连接会在常规连接失败后自动使用 IPv4 重试。若 Server 所在网络无法直连 Telegram，可在 `server.env` 设置 `TELEGRAM_PROXY_URL`，支持 `http://`、`https://`、`socks5://` 和 `socks5h://`；需要用户名密码时可使用 `socks5h://用户名:密码@代理地址:端口`。推荐 `socks5h://`，Telegram 域名会由代理端解析，可绕过 Server 本地 DNS 或 IPv6 路由问题。修改后执行 Server `update`。页面会区分常规连接、IPv4 回退和代理连接错误。

若宿主机同时运行 Docker 与 Podman，Docker 可能把全局 `FORWARD` 策略设为 `DROP` 并先于 netavark 拦截 Narwhal Server 容器流量。安装器会为 Narwhal 专用 Podman 子网在 `DOCKER-USER` 中加入最小范围的出站与已建立回程放行，并通过 systemd timer 每分钟幂等检查；不会开放新的宿主机入站端口。

活动告警可在总览页面查看，也可查询：

```bash
dashboard_user="$(sudo awk -F= '$1=="DASHBOARD_USERNAME"{print substr($0,index($0,"=")+1);exit}' /opt/narwhal-monitor/server.env)"
dashboard_password="$(sudo awk -F= '$1=="DASHBOARD_PASSWORD"{print substr($0,index($0,"=")+1);exit}' /opt/narwhal-monitor/server.env)"
curl -su "$dashboard_user:$dashboard_password" http://127.0.0.1:8080/api/v1/security/alerts | jq
curl -su "$dashboard_user:$dashboard_password" 'http://127.0.0.1:8080/api/v1/security/alerts?active_only=false&limit=200' | jq
curl -su "$dashboard_user:$dashboard_password" http://127.0.0.1:8080/api/v1/security/status | jq
curl -su "$dashboard_user:$dashboard_password" http://127.0.0.1:8080/api/v1/security/actions | jq
```

> 阈值必须按机器带宽、正常高峰 RPS 和业务连接模型校准。除连接数严格大于 1500 连续满 1 小时会自动停止目标容器，以及管理员在页面二次确认的机场对接“快速清理”外，其余配置风险只告警，不会自动修改 Incus/Podman 配置或封禁流量。扫描检测基于内核累计计数器与采样时仍存在的 socket，是轻量级异常检测；如果需要逐次 `execve/connect/open` 事件、反弹 Shell、落地新二进制和容器逃逸检测，应在节点额外部署 Falco/eBPF 运行时安全组件。“滥用”表示行为异常线索，最终定性仍需结合供应商投诉、认证日志和业务审计。

## RFW 母机防火墙集中策略

RFW 策略由管理员在平台“运维中心 → 主机防火墙”查看和维护。单机策略适合验证；全局模板适合批量变更，会覆盖各节点原有的 Narwhal 管理策略。Watcher 将版本化策略排入每台已注册节点的安全动作队列，经现有 HMAC 上报/领取通道送到 Client，再通过 Runman 的本地 `firewall.sock` 控制接口与节点 RFW API 对接。Runman 只自动删除自己登记的规则；手工 RFW 规则可在新鲜读回后逐条确认删除，或复制到网页策略草稿中迁移；全局页可查看节点状态、应用回执与 RFW 实际规则读回。应用回执/用户态规则读回不是 eBPF 内核 map 的逐项证明。

GeoIP `CN` 规则按**方向**解释地址：入站匹配来源 IP，出站匹配目标 IP。要禁止母机或容器流量直连中国地址，应添加 `out + CN + block` 规则；SOCKS、WireGuard、FET、MTProto 可在规则页用出站预置一次加入并通过全局模板批量同步。带 `CN` 的放行/阻断事件会进入安全告警与 Telegram 通知；阻断事件是处置结果，放行事件是仍需注意的严重风险。混合国家 GeoIP 规则可能只证明规则范围包含 CN，告警会标注“实际命中国家未知”，不冒充精确地理归属。

协议识别是首包/首报文特征，不进行 TCP 重组：SOCKS 识别握手，WireGuard 识别初始握手报文，MTProto 识别已知混淆传输初始化标记。Shadowsocks 没有可可靠匹配的固定明文签名；`FET` 仅表示高熵加密流量特征，可能覆盖部分 SS 类流量，也可能命中其他非 TLS 加密协议，不能作为已确认 Shadowsocks 的证据。使用 FET 阻断前应确认误报影响范围。策略依赖的应用层协议能力未知、过期或不支持时，节点会延迟同步，直到收到新鲜能力读回或升级支持；不会先盲目下发再失败。当前 RFW 每台主机按单接口、单实例运行，平台不把逗号分隔的多个网卡伪装成多接口支持。

## HTTPS 配置指引

> 三种方式都会由 Caddy 自动续期证书，无需手工续期。域名方式使用公网 CA；IP 方式使用由 Client 自动信任的内部 CA。

### 方式 A：域名直连（ACME HTTP-01，最简单）

适用：你使用 Cloudflare 托管 DNS，但可将该记录设置为 **DNS only（灰云）**。

1. 在 Cloudflare DNS 中为你的主机新增 `A/AAAA` 记录（例如 `monitor.example.com`）指向服务器公网 IP。  
2. 将该记录设置为 **DNS only（灰云）**，不要走 Cloudflare 代理。  
3. 服务器放通 `80/443` 端口。  
4. 运行安装脚本时填写：
   - `Enable HTTPS reverse proxy`: `yes`
   - `TLS host`: `monitor.example.com`
   - `TLS cert mode`: `auto`（域名下会自动走公网 ACME）
   - `TLS email`: 建议填写
5. Client 端 `SERVER_URL` 使用 `https://monitor.example.com`。

### 方式 B：Cloudflare DNS Challenge（可橙云）

适用：你希望保留 Cloudflare 代理（橙云）或不便开放 80 端口。

1. 在 Cloudflare 创建 API Token，权限至少包含：
   - `Zone:DNS:Edit`
   - `Zone:Zone:Read`
2. 运行安装脚本时填写：
   - `Enable HTTPS reverse proxy`: `yes`
   - `TLS host`: `monitor.example.com`
   - `TLS cert mode`: `cloudflare_dns`
   - `Cloudflare API token`: 填入上一步 token
3. 脚本会自动使用带 Cloudflare DNS 模块的 Caddy 镜像（优先 `ghcr.io/caddy-dns/cloudflare:latest`，并带回退策略），并注入 token。若你填了旧地址 `docker.io/caddy-dns/cloudflare`，安装脚本会自动改写到 `ghcr.io`。  
4. Client 端 `SERVER_URL` 使用 `https://monitor.example.com`。

> 安全建议：Cloudflare Token 请仅授予单一 Zone 的最小权限，避免使用全局 API Key。

### 方式 C：直接使用 IP（内部 CA）

适用：暂时没有域名，但仍希望 Client 到 Server 的链路保持完整 TLS 校验。

1. Server 安装时填写：
   - `Enable HTTPS reverse proxy`: `yes`
   - `TLS host`: Server 公网 IP
   - `TLS cert mode`: `auto` 或 `internal`
2. Server 会生成内部 CA，并只把公开根证书导出到 `/opt/narwhal-monitor/tls-ca/root.crt`；根私钥不会挂载到 Server 应用容器，也不会传给 Client。
3. Client 的 `SERVER_URL` 填写 `https://SERVER_IP`，不要追加安装摘要中的随机 Backend Port。
4. Client 安装器发现系统不信任该证书后，会访问 `/api/v1/tls/ca`。请求与响应都通过 `SHARED_SECRET` 做 HMAC-SHA256 校验，校验成功后把证书保存到 `/opt/narwhal-monitor/server-ca.crt`，并写入 `SERVER_TLS_CA_FILE`。
5. 如果共享密钥错误、响应被篡改、证书主机名不匹配或最终 TLS 校验失败，Client 安装会直接中止，不会降级为跳过证书验证。

## 宿主机原始值一键采集（排查/改造前确认）

在任意宿主机执行：

```bash
curl -fsSL https://raw.githubusercontent.com/podcctv/Narwhal-Cloud-podman-watcher/main/scripts/collect-podman-raw.sh -o /tmp/collect-podman-raw.sh
chmod +x /tmp/collect-podman-raw.sh
sudo /tmp/collect-podman-raw.sh
```

或在本仓库里直接执行：

```bash
sudo bash scripts/collect-podman-raw.sh
```

输出为 `/tmp/podman-raw-<UTC时间戳>.tar.gz`，包含宿主机与容器的原始指标（CPU 计数器、线程/进程、内存、网络 IO、容器 inspect/stats/top 等）。将压缩包回传后，可按真实字段改造成“Client 原始值透传，Server 统一统计分析”。

## 在线验证清单（仍显示 0 时）

> 目标：按“采集 → 上报 → 入库 → 展示”链路逐层定位，到底卡在哪一层。

### 1) 先看 Client 服务是否在稳定上报

```bash
sudo systemctl status narwhal-monitor-client --no-pager
sudo journalctl -u narwhal-monitor-client -n 120 --no-pager
```

重点看日志里是否持续出现：
- `reported X containers to ...`（上报成功）
- `report failed: ...`（上报失败，优先处理网络/证书/签名）

### 2) 在 Client 宿主机直接验证容器原始采集

```bash
podman ps --format '{{.ID}}|{{.Names}}|{{.Image}}'
podman stats --no-stream --format json <容器名>
podman stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}' <容器名>
podman inspect <容器名> --format '{{.State.Pid}}'

docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}'
docker stats --no-stream --format json <容器名>
docker inspect <容器名> --format '{{.State.Pid}}'

incus list type=container status=running --format json
incus query /1.0/metrics | grep 'name="<容器名>"'
incus query /1.0/instances/<容器名>/state
```

可直接用仓库脚本对**单个容器**做与 Agent 同口径的排查（例如你机器上的 `fuckip-agent`）：

```bash
sudo bash scripts/query-single-container.sh fuckip-agent
sudo bash scripts/query-single-container.sh fuckip-agent docker
sudo bash scripts/query-single-container.sh my-incus-container incus
```

判断标准：
- 如果 `stats` 任一格式有 CPU/网络值，Agent 会按字段择优使用。
- 如果 `stats` 网络字段为空，Agent 会尝试从 `/proc/<pid>/net/dev` 读累计 RX/TX。

### 3) 在 Server 侧直接看 API 最新值（绕开前端）

```bash
curl -s http://127.0.0.1:8080/api/v1/latest | jq '.items[] | {host_id,container_name,cpu_percent,net_rx_bps,net_tx_bps,conn_count,timestamp_iso_utc8}'
```

若这里已经是非 0，而页面还是 0，说明是前端展示缓存/刷新问题。

### 4) 直接查数据库，确认是否入库为 0

```bash
sqlite3 /opt/narwhal-monitor/server-data/monitor.db "
SELECT host_id, container_name, cpu_percent, net_rx_bps, net_tx_bps, conn_count, ts
FROM reports
ORDER BY id DESC
LIMIT 20;"
```

判断：
- DB 就是 0：问题在 Client 采集或上报前处理。
- DB 非 0 但 API/页面是 0：问题在 Server 查询/聚合或前端显示。

### 5) 抓一次完整原始包（用于精确复盘）

```bash
sudo bash scripts/collect-podman-raw.sh
```

把输出的 `/tmp/podman-raw-*.tar.gz` 留存，用于逐字段比对（stats/inspect/top/proc）。

## 监控项

- 容器 CPU 占用
- 容器连接数（按容器 PID 统计 socket）
- 网络速度（RX/TX）
- 容器内当前 CPU 占用最高进程（PID / CPU% / 命令）
- 离线生命周期管理：整台主机失联超过 15 分钟即从总览隐藏，超过 1 天自动清理其关联数据；主机仍在线时，消失的单个容器保留 1 天后隐藏，历史样本最长保留 30 天
- 容器根盘容量，以及优先 `/data`、不存在时回退 `/` 的宿主机主盘容量与挂载点
- 容器网络健康（IPv4 / IPv6，跨 Podman/Docker/Incus 探测）
- 运行时与 Incus 项目维度，支持同主机同名容器隔离展示和历史统计
- DDoS、SYN Flood、HTTP/CC、端口扫描及出站滥用监测
- 告警去重、自动恢复、历史查询与可选 Webhook 通知
- 统计页到容器详情的一键跳转，以及进程、速率、暴露面和风险排查视图

## 容器权限说明

Server 为容器化部署，Client 改为宿主机 Agent（systemd）部署。

Client Agent 默认以 root 运行，直接通过宿主机 Podman、Docker、Incus CLI/socket 读取信息（无需嵌套运行容器引擎）。
Docker 需要可访问 Docker daemon；Incus 需要已完成 `incus admin init`（或连接到可用 remote）且 root 能访问目标项目。
如需进一步收敛权限，可在 Agent 中改为最小权限用户 + sudoers 精细授权。

## 架构选型建议（1G Server / <20 台设备）

在你的规模下（服务端内存约 1G，设备不到 20 台），推荐：

- **优先方案 A：HTTP 直传**
  - 架构简单，部署维护成本最低
  - 资源占用小，不需要额外维护 MQ 组件
  - 按 20 台 * 300s 上报间隔，中心端压力很低
- **方案 B：消息队列** 适合你未来明显扩容（例如 >100 台、需要削峰填谷、多消费者异步处理）时再引入

结论：**当前阶段选择方案 A 更合适**，后续若规模增长可平滑演进到 B。

## 开发运行

### Server

```bash
cd server
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8080
```

### Client

```bash
cd client
pip install -r requirements.txt
python agent.py --server http://127.0.0.1:8080 --secret change-me --interval 300
```
