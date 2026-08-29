# auto-vpnlink

自动发现、检查并聚合公开 VPN / Proxy 订阅源的项目。

> 本项目既可以**本地运行**，也可以使用 **GitHub Actions 自动运行**；GitHub Actions 不是本项目的必需依赖。

## ✨ 功能

- 🔎 搜索 GitHub / GitLab 等公开来源
- 🔍 发现订阅地址和节点 URI
- 📡 识别 VLESS / VMess / Shadowsocks / Trojan / Hysteria / TUIC
- 🧹 自动去重、健康检测和输出
- 🤖 GitHub Actions 定时运行
- 💻 支持直接克隆到本地运行
- ⏰ 本地使用 Python 标准库自动定时运行
- 🌐 自带 Web 控制台和管理员面板
- 🔐 管理员密码保护
- 🌍 管理员面板支持完整 IANA 时区选择
- ▶️ 管理员面板支持手动立即更新
- 💾 自动生成 `output/`

## 🚀 两种运行方式

本项目支持两种独立运行方式：

1. **本地 / VPS 运行**：直接克隆仓库，在自己的电脑、服务器或 VPS 上运行。
2. **GitHub Actions**：交给 GitHub 托管并按计划自动运行。

GitHub Actions **不是**本项目运行所必需的依赖。

---

## 💻 方式一：本地运行或 VPS 运行

### 1. 准备环境

需要 Python **3.12** 或兼容版本，以及 Git。

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

### 4. 单次运行

```bash
python scanner.py
```

### 5. 完整运行流程

```bash
python scanner.py
python augment_protocols.py
python select_nodes.py
python healthcheck.py
python publish_outputs.py
```

> ⚠️ 完整健康检测需要 Mihomo/Clash 内核。本地运行时请准备 Mihomo，并通过 `MIHOMO_BIN` 指定可执行文件路径。

---

## ⏰ 本地自动运行 + Web 服务器

项目自带 `local_server.py`。它同时负责：

- Python 内置定时器
- Web 服务器
- 管理员面板
- 自动任务设置
- 手动更新
- 密码管理
- 运行状态显示

**不需要** Windows 任务计划程序、Linux cron、systemd 或 macOS launchd。

启动：

```bash
python local_server.py
```

默认：

```text
每日自动运行：11:30
时区：Asia/Shanghai（UTC+8）
监听地址：0.0.0.0
端口：8080
```

### 🔐 首次运行管理员密码

第一次启动 `local_server.py` 时会自动生成一个随机管理员密码，并在**服务器终端中显示一次**。

密码之后不会再次显示，请立即保存。

密码哈希保存在：

```text
.auto_vpnlink_config.json
```

不要把这个文件提交到公开仓库。

也可以在服务器终端启动前通过环境变量指定初始密码：

```text
AUTO_VPN_ADMIN_PASSWORD=你的密码
```

### ⚙️ 管理员面板

打开：

```text
http://127.0.0.1:8080/admin
```

管理员登录后可以：

- ⏰ 设置每天几点自动运行
- 🌍 选择时区
- 📅 查看下一次运行时间
- ▶️ 手动立即执行一次完整更新
- 🔄 查看当前运行状态
- 🕐 查看上一次运行结果
- 🔑 设置自定义固定管理员密码
- 🎲 生成新的随机管理员密码
- 🚪 退出管理员登录

### 🌍 IANA 时区

管理员面板的时区下拉列表使用 Python `zoneinfo` 提供的 IANA 时区数据库动态生成，而不是只写死几个国家。

因此可以选择类似：

```text
Asia/Shanghai
Asia/Tokyo
Asia/Seoul
Asia/Singapore
Europe/London
Europe/Paris
America/Los_Angeles
America/New_York
Australia/Sydney
UTC
```

以及运行环境 `zoneinfo` 数据库中提供的其他 IANA 时区。

保存时区后，下一次自动运行时间会按照所选时区重新计算。

### 🌐 Web 地址

本机：

```text
http://127.0.0.1:8080/local
```

局域网：

```text
http://服务器IP:8080/local
```

管理员面板：

```text
http://服务器IP:8080/admin
```

### 🔒 IP 和端口只能在服务器终端设置

IP 和端口**不会放在管理员网页里修改**。

默认：

```text
AUTO_VPN_HOST=0.0.0.0
AUTO_VPN_PORT=8080
```

例如：

```bash
AUTO_VPN_HOST=0.0.0.0 AUTO_VPN_PORT=9000 python local_server.py
```

然后访问：

```text
http://服务器IP:9000/local
```

密码虽然可以在管理员面板修改，但初始密码也可以通过服务器终端环境变量设置。

> ⚠️ 如果直接暴露到公网，请配置防火墙、HTTPS、反向代理和访问控制。不要把未保护的管理服务直接暴露到互联网。

---

## 🤖 方式二：GitHub Actions

### 1. Fork

点击 **Fork → Create fork**，复制到自己的 GitHub 账号。

### 2. 手动运行

进入：

```text
Actions
 → Update VPN Sources
 → Run workflow
```

可以设置：

| 参数 | 说明 | 默认值 |
|---|---|---:|
| `search_limit` | 最多处理的发现节点 | `5000` |
| `health_candidate_limit` | 普通健康检测候选数量 | `300` |
| `health_success_target` | 普通健康检测成功目标 | `20` |
| `cfw_candidate_limit` | CFW 检测候选数量 | `150` |
| `cfw_success_target` | CFW 健康节点目标 | `10` |

成功目标是停止条件，并不保证最终一定能得到该数量的可用节点。

### 3. 自动运行

Workflow：

```text
.github/workflows/update.yml
```

默认每天 **北京时间 11:30** 自动运行一次。

```text
时区：Asia/Shanghai
时间：11:30
```

---

## 📄 GitHub Pages（可选）

```text
Settings
 → Pages
 → Build and deployment
 → Source: Deploy from a branch
 → Branch: main
 → Folder: / (root)
 → Save
```

GitHub Pages 不是项目运行所必需的。

---

## 🔄 工作流程

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

---

## 🚀 直接使用生成的订阅

运行成功后，结果位于：

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

### Base64

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/base64.txt
```

### 订阅源列表

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/subscriptions.txt
```

### 原始节点

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/nodes.txt
```

## 📁 输出文件

```text
output/
├── clash.yaml
├── clash-providers.yaml
├── base64.txt
├── nodes.txt
├── subscriptions.txt
├── sources.json
└── summary.md
```

## ⚠️ 关于“可用”

健康检测是在执行检测的机器上进行的。GitHub Actions 检测通过，不代表节点在你的本地网络、地区或客户端中一定可以连接。

## 🔐 安全

- 不要提交私有订阅链接。
- 不要提交 `.auto_vpnlink_config.json`。
- 不要把管理员密码、Token、Cookie 放入仓库。
- 公网部署管理面板时使用 HTTPS 和访问控制。
- 遵守 GitHub、GitLab、订阅源和网络服务的使用条款。

## 📜 License

目前仓库中没有单独声明开源协议。
