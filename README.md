# Narwhal Cloud Container Watcher (CS)

一个轻量级的 **CS 架构多运行时容器监控工具**，可在同一宿主机同时采集 **Podman、Docker 和 Incus 容器**：

- **Server 主控端**：汇总多机容器状态、网络状态与预警，提供 Web 页面。
- **Client 宿主机 Agent**：以 systemd 服务方式运行在宿主机，按固定间隔采集数据并上报。
- **通信安全**：`HMAC-SHA256` 共享密钥签名鉴权。
- **面板登录保护**：Server 安装时随机生成 Web 用户名和密码，使用 HTTP Basic Authentication 保护页面及管理 API。
- **部署方式**：Server 容器化 + Client 宿主机 Agent，支持一键安装与一键更新。
- **多运行时发现**：默认 `auto` 自动发现全部已安装运行时，也可显式指定组合。

## 主要能力

- **Podman / Incus 完整监测**：采集资源、网络、进程、监听端口、运行时暴露信息与安全风险。
- **Docker 默认仅提醒**：默认只发现 Docker 容器并展示信息提醒，不执行深度检查；可显式切换为完整监测或关闭发现。
- **节点侧安全检测**：针对 DDoS、CC、扫描、异常出站、可疑进程、危险容器配置和机场面板对接进行检测与预警。
- **NAT 场景识别**：不依赖 80/443 等固定端口，结合全部监听端口、运行时端口映射、进程、配置与面板域名判断。
- **OpenRC/Incus 清理兼容**：若非特权 Incus 容器内 UID 映射导致 `kill` 返回 `EPERM`，Agent 会从宿主机进入目标容器的 PID/挂载命名空间，重新核验精确进程名后终止进程；仍不会停止容器。
- **一键安装与更新**：`install.sh` 支持安装、更新和卸载；更新会复用 `/opt/narwhal-monitor/*.env` 配置并重建或重启服务。
- **告警快速处理**：活动告警可选择“禁止/持续拦截”“允许且不再提醒”或“本次取消提醒”；Podman/Incus 的机场面板对接告警支持定向清理，无认证 SOCKS 告警支持停止服务并持续拦截，Docker 不执行处理。
- **XMRig / XrayR 自动处置**：Podman/Incus 中精确命中的 XMRig 挖矿进程默认自动终止并清理明确的服务、配置和二进制；未获允许的 XrayR 节点后端默认自动定向清理。已加入域名白名单的合法 XrayR 不处理，Docker 仍只提醒。
- **告警历史与重新处置**：总览页可进入“告警历史”，按状态、级别、类型、主机和关键词筛选活动、已忽略、已处理及已恢复记录；可以对忽略记录重新禁止，也可以撤销“不再提醒”策略。
- **无认证 SOCKS 持续拦截**：Incus/Podman 的无认证或空密码 SOCKS 告警可一键停止对应进程/服务并保存节点侧策略；以后再次无认证启动会自动停止，检测到非空认证后自动解除策略。不会停止容器，也不会删除 SOCKS 配置或服务文件。
- **按需深度上报**：可在容器详情页对可疑的 Podman/Incus 容器发起一次性深度采样，在下一 Client 周期查看瞬时流量、详细进程、连接 IP 及进程归属；Docker 默认仅提醒，不执行该任务。
- **Server-first 自动更新**：Server 与 Client 默认每 15 分钟检查 GitHub `main`；Client 必须通过共享密钥签名确认 Server 已运行目标版本才会升级，避免 Client 版本提前。更新只进行安全的 fast-forward 并记录日志。
- **统一版本状态**：仓库根目录 `VERSION` 是 Server 与 Client 的唯一版本源；每台主机显示“最新、版本不一致或版本未知”，安装摘要也会显示当前版本。
- **Server HTTPS 自动化**：支持自动拉起 Caddy 反向代理：
  - 域名场景：自动申请公网证书（ACME HTTP-01）。
  - Cloudflare 域名场景：支持 DNS Challenge（可橙云），自动签发并续期公网证书。
  - IP 场景：自动签发内部证书（`tls internal`），Client 使用共享密钥认证并自动获取、校验和保存公开根证书。

> 注意：IP 场景下的内部证书不是公网 CA 证书。Client 安装器会自动建立信任，但浏览器仍可能提示不受信任；如需浏览器直接显示“绿锁”，建议使用域名和公网证书。

## 部署、更新与卸载

### 支持环境与部署方式

- 自动安装脚本面向 Debian / Ubuntu，依赖安装使用 `apt-get`，需要 root 权限。
- Server 部署为 Podman 容器；Client 部署为宿主机 systemd Agent。
- 推荐先在主控机部署一个 Server，再在每台客户节点部署 Client。Server 和 Client 可以安装在同一台机器，但生产环境通常分开部署。
- Client 节点应已安装需要监测的 Podman 或 Incus。若 Podman、Docker、Incus 均不存在，安装器会安装 Podman；安装器不会自动初始化 Incus。
- Server 与所有 Client 必须使用相同的 `SHARED_SECRET`。生产环境建议通过 HTTPS 上报，并妥善保存密钥。

### 首次部署

方式一：直接执行引导脚本。脚本会把仓库克隆到 `/opt/Narwhal-Cloud-podman-watcher`；目录已经存在时会以 fast-forward 方式更新，然后进入交互式安装器。

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

安装每台 Client 时依次选择：

1. 操作选择 `install`，目标选择 `client`。
2. `Server URL` 填写 Server 安装摘要中的 `Client Server URL`，例如 `https://monitor.example.com` 或 `https://10.0.0.2`。启用 Caddy 时不要追加随机 Backend Port；HTTPS 默认使用 443。
3. `Shared secret` 必须与 Server 完全一致；`Host ID` 必须在所有节点中唯一。
4. Client 会先使用系统 CA 验证 Server；如果是 IP/internal 模式，则通过 HMAC 认证接口获取公开根证书、验证响应签名并再次完成 TLS 校验。不会下载或传输 Caddy 根私钥。
5. 运行时建议保留 `auto`。Podman 与 Incus 默认完整监测；Docker 默认仅发现并提醒，不做深度扫描。
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

浏览器首次打开 Server 会弹出登录框。随机凭据只在首次安装摘要中显示，并保存在权限为 `0600` 的 Server 环境文件中；忘记时可在 Server 主机查看：

```bash
sudo awk -F= '$1=="DASHBOARD_USERNAME" || $1=="DASHBOARD_PASSWORD" {print $1"="substr($0,index($0,"=")+1)}' /opt/narwhal-monitor/server.env
```

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
INCUS_PROJECT=default
```

`auto` 会发现主机上可用的 Podman、Docker、Incus。Podman 和 Incus 默认做完整采集，两个过滤项默认都是 `*`，所以其中的 Xboard、xboard-node、Nginx/Caddy、数据库及其他运行中容器都会进入监测；只有明确需要缩小范围时才改成镜像或实例名关键字。Incus 虚拟机不在本项目的容器采集范围内。

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
`GEOIP_HTTPS_ENDPOINT`。私网 IP 不会发送到外部服务。结果使用有大小上限和过期时间的
内存缓存。对隐私要求更高时可设置 `GEOIP_HTTPS_ENABLED=false`，此时没有本地 MMDB 的
地址统一显示为 `UN`。GeoLite2 数据库需要按
[MaxMind 官方说明](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)自行获取和更新；
默认 HTTPS 回退接口为可自托管的 [country.is](https://github.com/lineofflight/country)。

连接数严格大于 `500` 时产生 warning，严格大于 `1000` 时升级为 critical。Server 会独立记录每个容器的连续超限窗口；连接数严格大于 `1500` 且连续满 15 分钟时，经 HMAC 签名动作通道自动停止该容器。若相邻超限样本间隔超过 600 秒，连续计时会重新开始，避免把上报中断误判为持续超限。

Agent 会同时读取宿主机 `SECURITY_ACCESS_LOG_PATHS`，并通过对应的 Podman/Docker/Incus 运行时进入每个容器读取 `SECURITY_CONTAINER_ACCESS_LOG_PATHS`。因此面板或反代日志既可以位于宿主机，也可以只存在于容器内部；文件不存在的容器会自动跳过。也可以把容器日志只读挂载到宿主机后，仅保留宿主机路径。日志不可读时网络层检测仍正常运行，但该容器不会产生 HTTP/CC 日志告警。

`SECURITY_ALLOWED_PANEL_DOMAINS` 是允许对接的面板域名白名单，支持父域匹配，例如配置 `example.com` 会允许 `panel.example.com`，但不会允许 `example.com.evil.test`。默认留空表示没有允许的第三方面板；发现明确面板域名时产生 critical 告警，只发现节点程序或配置特征但无法提取域名时产生 warning。检测过程不会把配置文件正文、API Key 或 Token 写入上报数据。

SOCKS 检测复用本轮已经读取的容器进程列表；只有发现 SOCKS 候选进程或容器身份特征时，才对 `SECURITY_SOCKS_CONFIG_PATHS` 中最多 30 个精确路径各读取前 256 KiB 并在容器内返回风险标记，不传输配置正文或凭据。无认证/弱密码且确认存在公网或 NAT 暴露时为 critical，未确认公网暴露时为 warning。弱密码判断包含常见默认密码和少于 8 位的命令行密码。

对于已确认 `no_auth` 的 Incus/Podman SOCKS 告警，面板会显示“停止并持续拦截”。确认后，Client 只停止本次检测命中的 SOCKS 进程及其精确 systemd/OpenRC 服务，不禁用或删除服务，不删除配置，也不停止容器。策略按运行时、Incus 项目和容器名称写入 `SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE`；以后正常采集周期复用既有 SOCKS 认证检测结果，如果该容器再次以无认证或空密码方式运行就再次停止。检测到 `configured` 或非空的 `weak_password` 认证后，Client 会自动删除该容器的持续拦截策略，允许服务恢复运行；弱密码本身仍会继续告警，供管理员决定是否放行。Docker 始终仅提醒，不显示此按钮。

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
- “访问日志”会区分宿主机日志正常、容器日志正常、日志文件未发现、权限不足和未配置。节点侧 Agent 以 root 运行；若显示“未发现日志文件”，请将实际 Nginx/Caddy access log 路径加入 `SECURITY_ACCESS_LOG_PATHS`（宿主机）或 `SECURITY_CONTAINER_ACCESS_LOG_PATHS`（容器内），更新 Client 后生效。
- 入站去重 IP 优先通过宿主机 conntrack 与端口映射还原真实公网来源，兼容 Incus proxy、`incus network forward`、宿主机 iptables/nftables DNAT、唯一 PID 用户态转发和 Podman 端口映射；`10.x` 等代理网关地址不会冒充公网来源，不可还原时明确回退到容器网络命名空间的 `/proc/net`。默认只有数量大于 `ALERT_INBOUND_UNIQUE_IPS=10` 才产生重点告警。每轮最多读取 5000 条 conntrack 和 5000 条宿主机代理 socket 记录，Incus 网络转发配置每 4 分钟最多读取一次，并通过一次最多 500 条的容器 `ss` 快照把目标端口归属到通信进程，默认最多上报 100 条活动连接；全程不抓包、不扫描文件，不持续占用 CPU。同一代理 PID 对应多个容器目标时不会猜测归属，避免误告警。
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
CONNECTION_STOP_DURATION_SECONDS=900
CONNECTION_STOP_MAX_GAP_SECONDS=600
OFFLINE_HOST_PURGE_SECONDS=86400
DASHBOARD_USERNAME=安装时随机生成
DASHBOARD_PASSWORD=安装时随机生成
```

Webhook 仅在告警首次出现、级别升级或恢复后再次出现时发送，正文格式为：

```json
{"event":"narwhal.security_alert","alert":{"host_id":"host-1","type":"ddos_packets","severity":"warning","message":"..."}}
```

活动告警可在总览页面查看，也可查询：

```bash
dashboard_user="$(sudo awk -F= '$1=="DASHBOARD_USERNAME"{print substr($0,index($0,"=")+1);exit}' /opt/narwhal-monitor/server.env)"
dashboard_password="$(sudo awk -F= '$1=="DASHBOARD_PASSWORD"{print substr($0,index($0,"=")+1);exit}' /opt/narwhal-monitor/server.env)"
curl -su "$dashboard_user:$dashboard_password" http://127.0.0.1:8080/api/v1/security/alerts | jq
curl -su "$dashboard_user:$dashboard_password" 'http://127.0.0.1:8080/api/v1/security/alerts?active_only=false&limit=200' | jq
curl -su "$dashboard_user:$dashboard_password" http://127.0.0.1:8080/api/v1/security/status | jq
curl -su "$dashboard_user:$dashboard_password" http://127.0.0.1:8080/api/v1/security/actions | jq
```

> 阈值必须按机器带宽、正常高峰 RPS 和业务连接模型校准。除连接数严格大于 1500 持续 15 分钟会自动停止目标容器，以及管理员在页面二次确认的机场对接“快速清理”外，其余配置风险只告警，不会自动修改 Incus/Podman 配置或封禁流量。扫描检测基于内核累计计数器与采样时仍存在的 socket，是轻量级异常检测；如果需要逐次 `execve/connect/open` 事件、反弹 Shell、落地新二进制和容器逃逸检测，应在节点额外部署 Falco/eBPF 运行时安全组件。“滥用”表示行为异常线索，最终定性仍需结合供应商投诉、认证日志和业务审计。

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
