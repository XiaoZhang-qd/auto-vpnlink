# auto-vpnlink

自动发现、检查并聚合公开 VPN / Proxy 订阅源的 GitHub Actions 项目。

> 本项目只处理公开数据。**订阅地址可访问不代表其中每一个节点都一定可连接。**

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
- ▶️ 支持 Actions 手动更新
- 💾 自动提交最新 `output/`

## 🚀 最重要：直接使用生成的订阅

Action 成功运行后，`output/` 会自动更新。

### Clash / Mihomo

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/clash.yaml
```

这是自动把发现到的 VLESS / VMess / Trojan / Shadowsocks 等 URI 转成 Clash/Mihomo YAML 后生成的文件。

### Base64 节点列表

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/base64.txt
```

里面是聚合后的节点 URI 的 Base64 内容，适用于支持这种订阅形式的客户端。

### 原始订阅源列表

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/subscriptions.txt
```

这个文件是**订阅源地址清单**，不是一个统一的 Clash 配置，因此不要把它误认为单一订阅配置。

### 原始节点

```text
https://raw.githubusercontent.com/XiaoZhang-qd/auto-vpnlink/main/output/nodes.txt
```

这里保存扫描时直接发现的 VLESS / VMess / SS / Trojan / Hysteria / TUIC URI。

## 📁 输出文件

```text
output/
├── clash.yaml              # ⭐ 聚合后的 Clash/Mihomo YAML
├── clash-providers.yaml    # 已经是兼容订阅源的 Provider 列表
├── base64.txt              # ⭐ 聚合节点 Base64
├── nodes.txt               # 原始节点 URI
├── subscriptions.txt       # 检测通过的订阅 URL
├── sources.json             # 完整来源、检测及统计信息
└── summary.md              # 本次扫描摘要
```

### `clash.yaml`

这是项目最重要的聚合结果之一。程序会把直接发现的节点 URI 转换成 Clash/Mihomo `proxies`，并自动建立一个 `AUTO` url-test 分组。

> 不同协议的高级传输参数并不一定能从 URI 完整推断，因此这是自动聚合结果，不保证每个转换后的节点都能连接。

### `clash-providers.yaml`

对于原本就返回 Clash/Provider 风格配置的订阅地址，程序会保留其 URL，并生成 Provider 配置。

### `base64.txt`

聚合后的节点 URI Base64 编码结果。

### `subscriptions.txt`

经过 HTTP 检查并且内容看起来像订阅/节点数据的 URL 列表。

### `sources.json`

保存仓库来源、发现的 URL、检测结果以及统计信息，方便以后做网页/API 展示。

## 🔎 默认搜索来源

项目不会只搜索 `freevpn`，还会搜索 VPN、Proxy、Networking 和 DevOps 相关 Topic，例如：

```text
freevpn
vpn-subscription
proxy-list
clash
sing-box
v2ray
vless
vmess
shadowsocks
trojan
hysteria
devops
automation
networking
```

对于 `devops`、`automation`、`networking` 这类非常宽泛的 Topic，程序会进一步检查仓库名称和描述中的 VPN/Proxy 关键词，避免扫描大量无关仓库。

完整配置位于：

```text
sources.yaml
```

## 🌍 多 Git 平台

目前内置：

- GitHub Topics
- GitLab Topics
- 额外公开 Git 仓库

你可以在 `sources.yaml` 添加 Topic，也可以加入额外仓库。

```yaml
extra_repositories:
  - https://github.com/example/project.git
  - https://gitlab.com/example/project.git
```

扫描器只读取文本/配置内容，**不会执行陌生仓库中的代码**。

## ⚙️ 扫描限制

为了避免每天运行几十分钟甚至更久，扫描器采用限制策略：

```yaml
max_repositories_per_topic: 15
max_files_per_repository: 20
max_file_size: 800000
max_subscription_checks: 300
max_aggregate_nodes: 5000
workers: 8
```

这样可以在数据量、GitHub API 请求和运行时间之间保持平衡。

## 🤖 GitHub Actions

Workflow：

```text
.github/workflows/update.yml
```

每天北京时间 **10:15** 自动运行，也可以手动运行：

```text
GitHub
 → Actions
 → Update VPN Sources
 → Run workflow
```

Action 会：

```text
发现来源
   ↓
扫描文件
   ↓
提取 URL / 节点
   ↓
去重
   ↓
检测订阅
   ↓
聚合节点
   ↓
生成 output/
   ↓
自动 commit + push
```

## 🧪 本地运行

需要 Python 3.12 或兼容版本：

```bash
pip install -r requirements.txt
python scanner.py
```

## ⚠️ 关于“可用”

这里的“可用”主要表示：

1. URL 可以通过 HTTP/HTTPS 访问；
2. 返回内容能够识别为订阅、节点 URI 或 Clash 配置；
3. 对直接发现的节点，可以进行格式识别和聚合。

**这不等于实际 VPN 连接一定成功。** 免费节点可能很快失效、过期、限速或受到地区限制。

## 🔐 安全

- 不要提交私有订阅链接。
- 不要把账号密码、Token、Cookie 放入仓库。
- 不执行第三方 Git 仓库中的程序。
- 请遵守 GitHub、GitLab、订阅源和网络服务的使用条款。

## 📜 License

目前仓库中没有单独声明开源协议。
