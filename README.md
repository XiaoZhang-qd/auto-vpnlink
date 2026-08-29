# auto-vpnlink

自动发现、检查并聚合公开 VPN / Proxy 订阅源的项目。

> 本项目既可以**本地运行**，也可以使用 **GitHub Actions 自动运行**；GitHub Actions 不是本项目的必需依赖。
>
> 本项目只处理公开数据。**订阅地址可访问不代表其中每一个节点都一定可连接。**
>
> 🌐 网络测试：[https://xiaozhang-qd.github.io/auto-vpnlink/](https://xiaozhang-qd.github.io/auto-vpnlink/)
>
> 📡 订阅链接：[https://xiaozhang-qd.github.io/auto-vpnlink/subscriptions.html](https://xiaozhang-qd.github.io/auto-vpnlink/subscriptions.html)

## ✨ 现在能做什么

- 🔎 搜索 GitHub Topics
- 🦊 搜索 GitLab Topics
- 📦 扫描额外公开 Git 仓库
- 🔍 从 README、TXT、YAML、JSON、配置文件等内容中发现订阅地址和节点 URI
- 📡 识别 VLESS / VMess / Shadowsocks / Trojan / Hysteria / TUIC
- 🧹 自动去重
- 🌐 检查发现的订阅 URL 是否可访问、内容是否像有效订阅
- 🔄 把发现到的节点聚合成客户端可用的输出
- 🤖 可通过 GitHub Actions 定时自动更新
- ▶️ 支持 GitHub Actions 手动更新，并可设置搜索/检测数量
- 💻 支持直接克隆到本地运行
- ⏰ 本地支持使用 Python 标准库每天自动运行
- 🌐 本地提供 Web 控制台，可作为简单网站/服务器运行
- 💾 自动生成并更新 `output/`

## 🚀 部署与使用

本项目支持两种独立运行方式：

1. **本地运行**：直接克隆仓库，在自己的电脑、服务器或 VPS 上运行。
2. **GitHub Actions**：交给 GitHub 托管并按计划自动运行。

> ⚠️ GitHub Actions 不是本项目的必需依赖。核心程序可以脱离 GitHub Actions 在本地运行。

---

## 💻 方式一：本地运行

### 1. 准备环境

需要：

- Python **3.12** 或兼容版本
- Git
- 能够访问项目所需的网络资源

确认环境：

```bash
python --version
git --version
```

### 2. 克隆仓库

```bash
git clone https://github.com/XiaoZhang-qd/auto-vpnlink.git
cd auto-vpnlink
```

### 3. 安装依赖

```bash
python -m pip install -r requirements.txt
```

### 4. 最简单的运行方式

```bash
python scanner.py
```

程序完成后会生成或更新 `output/` 中的结果。

### 5. 完整运行流程

如果需要执行项目完整处理流程，可以依次运行：

```bash
python scanner.py
python augment_protocols.py
python select_nodes.py
python healthcheck.py
python publish_outputs.py
```

> ⚠️ 完整流程中的健康检测需要可用的 Mihomo/Clash 内核。本地运行时请准备 Mihomo，并通过 `MIHOMO_BIN` 指定可执行文件路径。

---

## ⏰ 本地自动运行

项目自带基于 **Python 标准库**实现的本地定时器，**不需要 Windows 任务计划程序、Linux cron、systemd 或 macOS launchd**。

启动本地自动运行服务：

```bash
python local_server.py
```

默认配置：

```text
每天：11:30
时区：Asia/Shanghai（UTC+8）
```

程序会一直运行，并在每天北京时间 11:30 自动执行一次完整处理流程。

### 自定义自动运行时间

可以通过环境变量修改每日运行时间和时区。

Linux / macOS：

```bash
AUTO_VPN_TIME=08:00 AUTO_VPN_TIMEZONE=Asia/Shanghai python local_server.py
```

Windows PowerShell：

```powershell
$env:AUTO_VPN_TIME="08:00"
$env:AUTO_VPN_TIMEZONE="Asia/Shanghai"
python local_server.py
```

例如设置 `08:00` 后，程序就会每天北京时间 08:00 自动运行。

> ⚠️ 本地定时器依赖 `local_server.py` 持续运行。停止 Python 进程后，自动任务也会停止。

---

## 🌐 本地 Web 服务器

`local_server.py` 同时提供一个 Web 控制台，因此它既是**本地自动任务程序**，也是一个简单的 Web 服务器。

启动：

```bash
python local_server.py
```

本机打开：

```text
http://127.0.0.1:8080/local
```

如果运行在局域网服务器上，同一网络中的其他设备可以访问：

```text
http://服务器IP:8080/local
```

例如：

```text
http://192.168.1.100:8080/local
```

### Web 控制台功能

网页可以查看：

- ⏰ 每天自动运行时间
- 🌏 当前时区
- 📅 下一次计划运行时间
- 🔄 当前运行状态
- 🕐 上一次运行时间
- ✅ / ❌ 上一次运行结果
- 📜 最近一次运行日志
- ▶️ 手动立即执行一次完整流程
- 📡 快速进入订阅网页

同时，服务器也会提供项目目录中的网页和 `output/` 文件，因此可以把运行中的电脑、VPS 或服务器作为一个简单的网站服务器使用。

### 作为网站服务器运行

默认监听：

```text
0.0.0.0:8080
```

可以通过环境变量修改：

```text
AUTO_VPN_HOST=0.0.0.0
AUTO_VPN_PORT=8080
```

例如：

```bash
AUTO_VPN_PORT=9000 python local_server.py
```

然后访问：

```text
http://服务器IP:9000/local
```

> ⚠️ 如果直接暴露到公网，请自行配置防火墙、反向代理、HTTPS 和访问控制。当前 Web 控制台没有账号密码认证，不建议未经保护直接暴露到公网。

---

## 🤖 方式二：GitHub Actions 自动运行

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

项目默认通过 GitHub Actions **每天北京时间 11:30 自动运行一次**。

时区：`Asia/Shanghai`（UTC+8）

自动运行使用默认参数；需要调整搜索或检测规模时，可以手动执行 **Run workflow**。

### 4. GitHub Pages（可选）

如果希望通过 GitHub Pages 访问生成的网页和文件：

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

> 💡 **GitHub Pages 不是必须的。** 本地运行或直接使用 GitHub Raw 文件都不需要启用 Pages。

---

## 🔄 工作流程

每次完整运行大致按照以下流程执行：

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
更新 output/
```

GitHub Actions 模式会在最后自动提交生成结果；本地运行则由用户自行决定是否提交 Git 更改。

## 🚀 最重要：直接使用生成的订阅

运行成功后，生成的文件位于：

```text
output/
```

### Clash / Mihomo

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/clash.yaml
```

```text
https://xiaozhang-qd.github.io/auto-vpnlink/main/output/clash.yaml
```

### Base64 节点列表

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/base64.txt
```

```text
https://xiaozhang-qd.github.io/auto-vpnlink/main/output/base64.txt
```

### 原始订阅源列表

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/subscriptions.txt
```

```text
https://xiaozhang-qd.github.io/auto-vpnlink/main/output/subscriptions.txt
```

这个文件是**订阅源地址清单**，不是统一的 Clash 配置。

### 原始节点

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/nodes.txt
```

```text
https://xiaozhang-qd.github.io/auto-vpnlink/main/output/nodes.txt
```

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

## ⚠️ 关于“可用”

健康检测主要是在执行检测的机器上进行连接和公网访问测试。

因此：

> **GitHub Actions 检测通过，不等于节点在你的本地网络、地区或客户端中一定可以连接。**
>
> 同理，本地检测通过也只代表它在当前本地网络环境下通过了检测。

免费节点可能很快失效、过期、限速、限制地区或限制运营商。

## 🔐 安全

- 不要提交私有订阅链接。
- 不要把账号密码、Token、Cookie 放入仓库。
- 不执行第三方 Git 仓库中的程序。
- 如果把本地 Web 服务暴露到公网，请配置访问控制和 HTTPS。
- 请遵守 GitHub、GitLab、订阅源和网络服务的使用条款。

## 📜 License

目前仓库中没有单独声明开源协议。
