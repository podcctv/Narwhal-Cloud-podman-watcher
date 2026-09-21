# TypeSafe Jev MCP (Model Context Protocol) Server

本脚本提供了一个开箱即用、**零外部依赖（纯 Python 标准库实现）** 的通用 MCP 服务端，专用于将 TypeSafe 的旗舰 System One 决策模型 **Jev** 暴露给任何支持 MCP 的 AI Agent（如 Antigravity IDE、Claude Desktop、Claude Code、Cursor、Windsurf 等）。

---

## 🛠️ 包含的 MCP Tools 工具列表

| 工具名称 | 功能描述 | 核心入参 | 返回结果 |
| :--- | :--- | :--- | :--- |
| **`jev_choice`** | **封闭集选择与分类**：从提供的候选列表中选择最佳项 | `state`, `instructions`, `candidates` | `selected_choice`, `confidence`, 各选项概率 `probabilities` |
| **`jev_noul`** | **命题真值概率判定**：判断命题是否成立（0.0 ~ 1.0） | `state`, `instructions` | `probability`, `is_likely` (>0.5 为 true) |
| **`jev_score`** | **等级加权打分**：按有序档位（如严重级、优先级）进行量化评分 | `state`, `instructions`, `levels` | `score`, `confidence` |
| **`jev_gate`** | **安全与风控护栏**：在 Agent 执行破坏性命令/操作前进行拦截评估 | `action_or_content`, `safety_rule`, `risk_threshold` | `allowed` (bool), `risk_probability`, `verdict` |
| **`jev_batch`** | **并行批处理评估**：在单次 API 请求中对同一上下文提出多个问题 | `state`, `questions` (map) | `answers` 字典 |

---

## 🚀 快速测试验证

```bash
# 查看帮助与工具列表状态
python scripts/jev_mcp_server.py --test
```

---

## ⚙️ 接入各主流 Agent 配置方式

### 1. Antigravity IDE 配置
在用户全局配置文件 `~/.gemini/config/mcp_config.json`（或项目级 MCP 配置）中添加：

```json
{
  "mcpServers": {
    "typesafe-jev": {
      "command": "python",
      "args": ["c:/Users/Flanker/Narwhal-Cloud-podman-watcher/scripts/jev_mcp_server.py"],
      "env": {
        "TYPESAFE_API_KEY": "你的_TYPESAFE_API_KEY"
      }
    }
  }
}
```

### 2. Claude Desktop 配置
在 `%APPDATA%\Claude\claude_desktop_config.json` 中配置：

```json
{
  "mcpServers": {
    "typesafe-jev": {
      "command": "python",
      "args": ["c:/Users/Flanker/Narwhal-Cloud-podman-watcher/scripts/jev_mcp_server.py"],
      "env": {
        "TYPESAFE_API_KEY": "你的_TYPESAFE_API_KEY"
      }
    }
  }
}
```

### 3. Cursor 配置
1. 打开 **Settings** -> **Features** -> **MCP**；
2. 点击 **+ Add New MCP Server**；
3. 填入：
   - **Name**: `typesafe-jev`
   - **Type**: `command`
   - **Command**: `python c:/Users/Flanker/Narwhal-Cloud-podman-watcher/scripts/jev_mcp_server.py`
4. 在环境变量中设置 `TYPESAFE_API_KEY`。

### 4. Claude Code CLI
```bash
claude mcp add typesafe-jev python c:/Users/Flanker/Narwhal-Cloud-podman-watcher/scripts/jev_mcp_server.py
```
