# auto-vpnlink

自动发现、检查并聚合公开 VPN / Proxy 订阅源的 GitHub Actions 项目。

> 本项目只处理公开数据。**订阅地址可访问不代表其中每一个节点都一定可连接。**
>> 可以到[https://xiaozhang-qd.github.io/auto-vpnlink/](https://xiaozhang-qd.github.io/auto-vpnlink/)进行网络测试。
>> 可以到[https://xiaozhang-qd.github.io/auto-vpnlink/subscriptions.html](https://xiaozhang-qd.github.io/auto-vpnlink/subscriptions.html)获取订阅链接

## ✨ 现在能做什么

- 🔎 搜索 GitHub Topics
- 🦊 搜索 GitLab Topics
- 📦 扫描额外公开 Git 仓库
- 🔍 从 README、TXT、YAML、JSON、配置文件等内容中发现订阅地址和节点 URI
- 📡 识别 VLESS / VMess / Shadowsocks / Trojan / Hysteria / TUIC
- 🧹 自动去重
- 🌐 检查发现的订阅 URL 是否可访问、内容是否像有效订阅
- 🔄 把发现到的节点聚合成客户端可用的输出
- 🤖 GitHub Actions 每天自动更新
- ▶️ 支持 Actions 手动更新，并可设置搜索/检测数量
- 💾 自动提交最新 `output/`

## 🚀 部署与使用

### 1. Fork 仓库

点击右上角 **Fork → Create fork**，将本项目复制到你自己的 GitHub 账号。

### 2. 首次运行

进入你 Fork 后的仓库：

```text
Actions
 → Update VPN Sources
 → Run workflow
```

点击 **Run workflow** 后，可以根据需要调整以下参数：

| 参数 | 说明 | 默认值 | 范围 |
|---|---|---:|---:|
| `search_limit` | 最多处理多少个发现的节点 | `5000` | `1 ~ 20000` |
| `health_candidate_limit` | 普通健康检测的候选节点数量 | `300` | `1 ~ 5000` |
| `health_success_target` | 普通健康检测成功目标数量 | `20` | - |
| `cfw_candidate_limit` | CFW 兼容节点检测候选数量 | `150` | `1 ~ 2000` |
| `cfw_success_target` | CFW 健康节点成功目标数量 | `10` | - |

> 💡 不需要调整检测规模时，直接使用默认值即可。

参数说明：

- **`search_limit`**：控制本次最多处理多少个聚合发现节点。数量越大，通常能发现更多节点，但运行时间也会增加。
- **`health_candidate_limit`**：从发现结果中选择多少个节点进行普通健康检测。
- **`health_success_target`**：普通健康检测达到指定数量后，可以提前结束检测。
- **`cfw_candidate_limit`**：选择多少个 CFW 兼容节点进行专门检测。
- **`cfw_success_target`**：CFW 健康检测达到指定数量后，可以提前结束检测。

> ⚠️ **成功目标只是停止条件，不代表一定能够获得这么多节点。** 如果候选节点中没有足够的可用节点，最终数量可能低于目标值。

### 3. 自动更新

Workflow 文件：

```text
.github/workflows/update.yml
```

项目会通过 GitHub Actions **每天北京时间 11:30 自动运行一次**。

时区：`Asia/Shanghai`（UTC+8）

自动运行使用上述默认参数；需要调整搜索或检测规模时，可以手动执行 **Run workflow**。

### 4. GitHub Pages（可选）

如果希望通过 GitHub Pages 访问生成的文件：

```text
Settings
 → Pages
 → Build and deployment
 → Source: Deploy from a branch
 → Branch: main
 → Folder: / (root)
 → Save
```

等待 Pages 部署完成即可。

> 💡 **GitHub Pages 不是必须的。** 不启用 Pages 也可以直接使用 `raw.githubusercontent.com` 提供的订阅地址。

### 5. 工作流程

每次运行大致按照以下流程执行：

```text
搜索公开来源
    ↓
扫描文件
    ↓
提取订阅 URL / 节点 URI
    ↓
自动去重
    ↓
普通健康检测
    ↓
CFW 专用健康检测
    ↓
生成客户端配置
    ↓
验证输出
    ↓
自动提交 output/
```

### 6. 获取订阅

Action 成功运行后，生成的文件会自动更新到：

```text
output/
```

具体订阅地址请查看：

**[🚀 最重要：直接使用生成的订阅](#-最重要直接使用生成的订阅)**

## 🚀 最重要：直接使用生成的订阅

Action 成功运行后，`output/` 会自动更新。

### Clash / Mihomo

```URL
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/clash.yaml
```
```URL
https://xiaozhang-qd.github.io/auto-vpnlink/main/output/clash.yaml
```

这是自动把发现到的节点转换成 Clash/Mihomo YAML 后生成的文件。

### Base64 节点列表

```URL
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/base64.txt
```
```URL
https://xiaozhang-qd.github.io/auto-vpnlink/main/output/base64.txt
```

里面是聚合后的节点 URI 的 Base64 内容，适用于支持这种订阅形式的客户端。

### 原始订阅源列表

```URL
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/subscriptions.txt
```
```URL
https://xiaozhang-qd.github.io/auto-vpnlink/main/output/subscriptions.txt
```

这个文件是**订阅源地址清单**，不是一个统一的 Clash 配置，因此不要把它误认为单一订阅配置。

### 原始节点

```URL
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/nodes.txt
```
```URL
https://xiaozhang-qd.github.io/auto-vpnlink/main/output/nodes.txt
```

这里保存扫描时直接发现的节点 URI。

## 📁 输出文件

```text
output/
├── clash.yaml              # ⭐ 聚合后的 Clash/Mihomo YAML
├── clash-providers.yaml    # Provider 列表
├── base64.txt              # ⭐ 聚合节点 Base64
├── nodes.txt               # 原始节点 URI
├── subscriptions.txt       # 检测通过的订阅 URL
├── sources.json             # 完整来源、检测及统计信息
└── summary.md               # 本次扫描摘要
```

## 🧪 本地运行

需要 Python 3.12 或兼容版本：

```bash
pip install -r requirements.txt
python scanner.py
```

## ⚠️ 关于“可用”

健康检测主要是在 GitHub Actions runner 环境中进行连接和公网访问测试。

因此：

> **GitHub Actions 检测通过，不等于节点在你的本地网络、地区或客户端中一定可以连接。**

免费节点可能很快失效、过期、限速、限制地区或限制运营商。

## 🔐 安全

- 不要提交私有订阅链接。
- 不要把账号密码、Token、Cookie 放入仓库。
- 不执行第三方 Git 仓库中的程序。
- 请遵守 GitHub、GitLab、订阅源和网络服务的使用条款。

## 📜 License

目前仓库中没有单独声明开源协议。
