# 2026-10-22 依赖漏洞修复

扫描报告的 19 条记录包含同一问题的 GHSA / PYSEC 别名；不能把 `REVIEW` 等同于低风险。

| 组件 / 原版本 | 原报告记录 | 处理 |
| --- | --- | --- |
| certifi 2026.7.22 | GHSA-6q48-6c7w-9gw2 / PYSEC-2026-4320 | Agent requirements 增加 `>=2026.10.19` 下限，更新受影响虚拟环境并重启 Agent |
| urllib3 2.7.0 | GHSA-8988-9cw3-xx77、GHSA-gh4c-6fx4-qh6g、GHSA-vxq7-64xx-v4gw / PYSEC-2026-4175、4176、4177 | 增加 `>=2.8.0,<3` 下限 |
| 系统 jaraco.context 6.0.1 | GHSA-58pv-8j8x-9vj2 / PYSEC-2026-1469 | Debian 13 的 `6.0.1-1+deb13u1` 已回移补丁；核对 dpkg 版本、过滤器代码和路径越界 / 符号链接回归，不能根据 PyPI 元数据误判或用 pip 覆盖发行版包 |
| braces 3.0.3 | GHSA-vfj7-8cjw-p6xm | 没有已发布的官方修复版本；迁移 Tailwind 3→4，移除 chokidar 3 / micromatch / braces 依赖链，而非忽略告警或伪造版本 |
| echarts 5.6.0 | GHSA-fgmj-fm8m-jvvx | 升至 6.1.0，重新构建浏览器产物并回归图表 |
| postcss-selector-parser 6.1.4 | GHSA-rj75-hqrm-r3gf | 随旧 Tailwind 依赖链移除；若未来重新引入，测试要求至少 7.1.6 |
| source-map-js 1.2.1 | GHSA-68fv-2mgg-jv7q | 通过 overrides 保证每个副本至少 1.2.2 |
| vite 6.4.3 | GHSA-587h-7wmj-h5pm、GHSA-698v-4r3x-3vcv、GHSA-9jrq-w75r-8gcw、GHSA-r825-w8mm-5pxw、GHSA-rq7h-c2jc-7f22 | 保留 Vite 6 主版本，升至 6.4.5；不暴露开发服务器 |

Tailwind 使用官方迁移工具转换旧工具类、主题和 PostCSS 配置；tailwind-merge 同步升级至兼容 v4 的 3.x。配置和依赖变更之外不改变业务逻辑。

验收必须包含：干净依赖安装、npm audit（开发依赖也包括）、TypeScript/Vite 构建、Python 测试、登录/后台/图表/手机布局，以及目标主机实际版本、pip check、上报和容器状态。备份应压缩存放并保留回滚，不删除业务数据。静态版本测试只用于防止回退，不能代替在线漏洞数据库查询。

## 官方依据

- [certifi](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2)
- [urllib3 advisories](https://github.com/urllib3/urllib3/security/advisories)
- [Debian jaraco.context 回移补丁](https://security-tracker.debian.org/tracker/CVE-2026-23949)
- [braces 公告：没有已发布修复版本](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
- [ECharts XSS 修复](https://github.com/apache/echarts/pull/21608)
- [Tailwind 官方迁移说明](https://tailwindcss.com/docs/upgrade-guide)
