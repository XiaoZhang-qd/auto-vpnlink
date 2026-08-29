# auto-vpnlink

自动发现、检查并聚合公开 VPN / Proxy 订阅源的 GitHub Actions 项目。

> 本项目只处理公开数据。**订阅地址可访问不代表其中每一个节点都一定可连接。**
>> 可以到**[https://xiaozhang-qd.github.io/auto-vpnlink/](https://xiaozhang-qd.github.io/auto-vpnlink/)进行网络测试。

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

### 部署方法
1. 点击在左上角Fork此仓库 -> 点击``Create fork`` -> 进入仓库的Actions -> 选择 `Update VPN Sources` -> 点击Run workflow -> 设置好 `Maximum discovered nodes to consider` `Maximum nodes for general health check` `General healthy node target` `Maximum CFW-compatible nodes to test` `CFW healthy node target` 后点击Run workflow即可，完成后使用[直接使用生成的订阅](#🚀 最重要：直接使用生成的订阅)的链接即可
2. 点击在左上角的Settings -> 点击 `Pages` -> 在 `Branch` 里选择main和/ (root) -> 点击 Save即可，完成后使用[直接使用生成的订阅](#🚀 最重要：直接使用生成的订阅)的链接即可

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

## ⚙️ 可以设置的数值

从 GitHub Actions 手动运行时，可以直接在 **Run workflow** 页面设置下面 5 个数值，不需要修改代码。

进入：

```text
GitHub
 → Actions
 → Update VPN Sources
 → Run workflow
```

### 1. `search_limit` — 搜索节点数量

控制本次最多处理多少个聚合发现节点。

默认：`5000`

范围：`1 ~ 20000`

例如：

```text
5000
```

搜索量越大，发现的节点通常越多，但扫描时间和后续检测时间也会增加。

### 2. `health_candidate_limit` — 普通健康检测候选数量

控制从搜索结果中最多拿多少个节点进入普通健康检测。

默认：`300`

范围：`1 ~ 5000`

例如：

```text
300
```

如果搜索到了 5000 个节点，并不代表会全部进行连接测试；这个参数用于限制健康检测规模。

### 3. `health_success_target` — 普通健康节点目标数量

普通健康检测达到这个数量后即可停止继续检测。

默认：`20`

设置为：

```text
20
```

表示普通健康检测最多以获得 20 个通过节点为目标。

如果设置为 `0`，表示不因为成功数量提前停止，继续检测候选池。

### 4. `cfw_candidate_limit` — Clash for Windows 检测候选数量

控制最多拿多少个 CFW 兼容协议节点进行专门检测。

默认：`150`

范围：`1 ~ 2000`

目前 CFW 专用候选主要筛选：

```text
SS
SSR
VMess
Trojan
```

### 5. `cfw_success_target` — CFW 健康节点目标数量

控制 CFW 专用检测希望获得多少个通过节点。

默认：`10`

设置为：

```text
10
```

表示获得 10 个 CFW 健康节点后即可停止继续检测。

如果设置为 `0`，表示检测全部 CFW 候选，不因成功数量提前停止。

### ⭐ 推荐设置

如果你想兼顾速度和节点数量，可以使用：

```text
搜索节点：       5000
普通检测候选：   300
普通成功目标：   20
CFW检测候选：    150
CFW成功目标：    10
```

如果 Action 运行太慢，可以降低：

```text
搜索节点：       2000
普通检测候选：   100
普通成功目标：   10
CFW检测候选：    80
CFW成功目标：    5
```

如果希望尽量多检测，可以提高候选数量；但数量越大，运行时间通常越长。

> **注意：成功目标是停止条件，不是保证值。** 如果候选节点本身没有足够的可用节点，实际通过数量可能低于目标值。

## 🤖 GitHub Actions

Workflow：

```text
.github/workflows/update.yml
```

每天北京时间 **10:15** 自动运行，也可以手动运行。

### 手动运行

打开：

```text
GitHub
 → Actions
 → Update VPN Sources
 → Run workflow
```

点击 **Run workflow** 后，可以填写上述数值，然后开始运行。

如果没有看到 **Run workflow**，请确认当前打开的是仓库默认分支上的 `Update VPN Sources` workflow，并刷新 Actions 页面。

Action 会：

```text
设置搜索/检测数量
        ↓
发现来源
        ↓
扫描文件
        ↓
提取 URL / 节点
        ↓
去重
        ↓
普通健康检测
        ↓
CFW 专用健康检测
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
