# auto-vpnlink

自动发现、收集和更新公开 VPN / Proxy 订阅源的 GitHub Actions 项目。

> 本项目主要用于公开订阅源的自动化整理与可访问性检查。**订阅地址可访问不代表其中每一个节点都一定可以连接。**

## ✨ 功能

- 🔎 自动搜索 GitHub Topics
- 🦊 支持 GitLab Topics
- 📦 支持手动配置任意公开 Git 仓库
- 🔍 扫描文本、YAML、JSON、配置文件等常见文件
- 🔗 提取 HTTP/HTTPS 订阅地址
- 📡 识别 VLESS / VMess / Shadowsocks / Trojan / Hysteria / TUIC 等节点 URI
- 🧹 自动去重
- 🌐 检查订阅 URL 是否可以访问
- 📊 生成 JSON 结果和统计信息
- 🤖 GitHub Actions 每天自动运行
- ▶️ 支持 GitHub Actions 手动运行
- 💾 自动提交更新后的 `output/`

## 🔄 自动运行

Workflow 文件：

`.github/workflows/update.yml`

默认每天北京时间 **10:15** 自动运行，同时支持手动运行：

**GitHub → Actions → Update VPN Sources → Run workflow**

Workflow 同时提供 `workflow_dispatch`，因此你可以不等待定时任务，随时手动刷新数据。

## 🔎 默认搜索来源

项目不会只搜索 `freevpn`，默认会覆盖多种 VPN、Proxy、Networking 和 DevOps 相关 Topic，例如：

```text
freevpn
vpn
vpn-subscription
vpn-config
vpn-configs
proxy
proxies
proxy-list
clash
clash-config
clash-meta
sing-box
v2ray
v2ray-config
vless
vmess
shadowsocks
trojan
hysteria
devops
automation
networking
self-hosted
```

具体来源可以在 `sources.yaml` 中继续扩展。

## 🌍 多 Git 平台

除了 GitHub，还支持通过配置接入其他公开 Git 项目，例如 GitLab、Codeberg、Gitea 等能够通过 Git URL 获取的公开仓库。

把仓库地址加入：

```text
sources/extra-repositories.txt
```

例如：

```text
https://github.com/example/project.git
https://gitlab.com/example/project.git
https://codeberg.org/example/project.git
```

## 📁 输出文件

每次扫描后会更新 `output/`：

```text
output/
├── subscriptions.txt   # 检测通过的订阅 URL
├── nodes.txt           # 提取到的节点 URI
├── sources.json        # 完整扫描和检测结果
├── clash-sources.yaml  # Clash Provider 来源列表（如生成）
└── summary.md          # 扫描摘要（如生成）
```

### subscriptions.txt

适合查看和复制当前检测通过的订阅源：

```text
https://example.com/sub/xxx
https://example.com/clash.yaml
```

### nodes.txt

保存扫描过程中直接发现的节点 URI，例如：

```text
vless://...
vmess://...
ss://...
trojan://...
```

## ⚙️ 配置

主要配置文件：

```text
sources.yaml
```

你可以在那里增加或删除 Topic、GitLab 来源以及其他扫描选项。

额外 Git 仓库：

```text
sources/extra-repositories.txt
```

## 🚀 本地运行

需要 Python 3.12 或兼容版本。

```bash
pip install -r requirements.txt
python scanner.py
```

## 🤖 GitHub Actions

项目使用 GitHub Actions 自动运行：

```yaml
on:
  schedule:
    - cron: '15 2 * * *'
      timezone: Asia/Shanghai
  workflow_dispatch:
```

其中：

- `schedule`：每天自动运行
- `workflow_dispatch`：手动运行
- `permissions: contents: write`：允许 Action 把生成结果提交回仓库

GitHub Actions 使用内置的 `GITHUB_TOKEN` 访问 GitHub API，不需要把个人 Token 写进仓库代码。

## ⚠️ 注意事项

1. 本项目只处理公开可访问的 Git 数据和订阅地址。
2. 程序的“可用”主要表示订阅 URL 可以访问并且返回内容符合预期，不能保证其中每一个 VPN 节点都能建立代理连接。
3. 免费订阅源可能随时失效、过期、限速或被删除，因此结果会随着每日扫描变化。
4. 请遵守目标网站、代码托管平台以及订阅提供方的使用条款。
5. 不要将私有订阅、账号密码或访问令牌提交到仓库。

## 📜 License

目前仓库中没有开源协议声明
