<!-- Translated copies: README.zh-CN.md, README.ja.md, README.de.md, README.fr.md, README.es.md, README.pt-BR.md. Update them in the same change. -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.svg">
    <img src=".github/assets/logo-light.svg" alt="PromptZero" width="420">
  </picture>
</p>

<p align="center"><a href="README.md">English</a>&emsp;<b>简体中文</b>&emsp;<a href="README.ja.md">日本語</a>&emsp;<a href="README.de.md">Deutsch</a>&emsp;<a href="README.fr.md">Français</a>&emsp;<a href="README.es.md">Español</a>&emsp;<a href="README.pt-BR.md">Português</a></p>

<h3 align="center">像和真人对话一样操作你的 Flipper Zero —— 它会构建载荷、部署并运行它</h3>

<p align="center">面向 Flipper Zero 与 ESP32 Marauder 的自然语言操作器。<br>
Sub-GHz、NFC、RFID、IR、BadUSB 和 WiFi —— 由 Claude 驱动，由风险引擎把关。</p>

<p align="center">
  <a href="https://github.com/xunholy/promptzero/releases/latest"><img src="https://img.shields.io/github/v/release/xunholy/promptzero?label=release&color=7b5fd0" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-AGPL--3.0-3f6fd1" alt="Licence: AGPL-3.0"></a>
  <a href="https://github.com/xunholy/promptzero/actions/workflows/ci.yaml"><img src="https://github.com/xunholy/promptzero/actions/workflows/ci.yaml/badge.svg" alt="CI"></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white" alt="Go 1.26"></a>
  <a href="docs/reference/transports.md"><img src="https://img.shields.io/badge/platforms-Linux%2C_macOS%2C_Windows-2f9a5a" alt="Platforms: Linux, macOS, Windows"></a>
  <a href="scripts/claude-usage.py"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/xunholy/promptzero/main/.github/claude-usage.json" alt="Claude usage"></a>
</p>

<p align="center">
  <a href="#快速开始"><b>快速开始</b></a>&emsp;
  <a href="#功能介绍"><b>功能介绍</b></a>&emsp;
  <a href="#运行模式"><b>运行模式</b></a>&emsp;
  <a href="#安全模型"><b>安全</b></a>&emsp;
  <a href="docs/"><b>文档</b></a>
</p>

> [!CAUTION]
> **仅限授权使用。** PromptZero 会生成并运行 RF、NFC、RFID 和 HID 载荷 —— 在你拥有或已获得书面授权测试的范围之外，这些操作均属违法。请阅读 [`SECURITY.md`](SECURITY.md) 了解安全模型与威胁边界。本项目正在积极开发中；API 与工具会在次版本之间发生变化。
>
> *端到端由 [Claude](https://claude.ai) 构建。部署前请审查生成的载荷。*

<p align="center">
  <img src=".github/assets/web.png" alt="PromptZero web UI — chat, live Flipper viewport, file browser, audit log" width="900">
</p>

用一句话描述你想做的事。PromptZero 会通过 USB 串口或 BLE 与你的 Flipper Zero（以及可选的 ESP32 Marauder WiFi 开发板）通信，生成载荷、将其部署到 SD 卡并运行 —— 其间每一个高风险操作都会经过一道同意确认关卡，并被记入审计日志。

```
promptzero> make me a Starbucks WiFi captive portal
  Generated and deployed evil_portal to /ext/apps_data/evil_portal/index.html
  Evil portal started on Marauder devboard

promptzero> scan for nearby WiFi networks and deauth the strongest one
  Found 12 access points. Strongest: "NETGEAR-5G" (-31 dBm, channel 6)
  Selected AP 0. Deauth attack running...

promptzero> create a BadUSB payload that opens a reverse shell on Windows
  Generated and deployed badusb to /ext/badusb/generated_payload.txt
  Ready to execute - plug into target and run

promptzero> identify this device: /tmp/remote.jpg
  That's a Samsung BN59 series TV remote using the Samsung32 IR protocol.
  I can generate a complete remote file. Want me to create it?
```

## 快速开始

**前置条件** —— 一台运行改装固件（Momentum / Unleashed / RogueMaster）的 Flipper Zero、一个 Anthropic API 密钥，以及一根 USB 线缆。

```bash
# 1. Install (Linux/macOS, amd64/arm64) — pinned to release artifacts (immutable per tag)
curl -fsSL https://github.com/xunholy/promptzero/releases/latest/download/install.sh | sh

# 2. Configure
export ANTHROPIC_API_KEY="sk-ant-..."

# 3. Run
promptzero
```

```
promptzero> what's connected?
  Flipper Zero — firmware 0.99.1, hardware v7.4
  Battery 84 % | SD card 4.1 GB free / 7.4 GB total
```

整个上手流程就这么多。从这里开始，输入自然语言指令，或输入 `/help` 查看斜杠命令。

> [!TIP]
> **防御姿态（单一标志的安全护栏）：** 加上 `--read-only` 即可拒绝任何会写入、发射或执行的工具。纯读取 / 扫描 / 查询仍会照常派发；任何风险为 Medium 或以上的操作都会在边界处被拒绝。
>
> ```bash
> promptzero --read-only          # blue-team / forensics / training
> ```

**其他方式：** Windows 用户可从[发布页面](https://github.com/xunholy/promptzero/releases)获取 `.zip`。WSL2 需要 USB 直通 —— 参见 [Transports → WSL2](docs/reference/transports.md#wsl2-usb-passthrough)。关于无线 BLE、配置文件、人格（persona）、环境变量和自升级：参见[配置参考](docs/reference/configuration.md)。

## 功能介绍

PromptZero 通过自然语言控制一切 —— 一个 agent、一个随版本迭代不断扩充的实时工具注册表，以及一道挡在任何会触及现实世界的操作之前的风险关卡。

| 子系统 | 能力 |
|---|---|
| **Flipper Zero** | Sub-GHz TX/RX、IR TX/RX、NFC 检测/模拟、RFID 读/写/模拟、iButton、GPIO、BadUSB、存储、应用启动器 |
| **ESP32 Marauder** | WiFi 扫描、deauth、信标泛洪（beacon spam）、探测泛洪（probe flood）、PMKID 捕获、evil portal、BLE 泛洪、BT 扫描、读卡器（skimmer）检测、wardriving、MAC 伪造 |
| **AI 生成** | 从自然语言生成 evil portal HTML、BadUSB DuckyScript、Sub-GHz `.sub`、IR `.ir`、NFC `.nfc` —— 还有针对类型化参数的参数化构建器 |
| **情报** | 通过 Claude vision 进行图像分析（文件路径 → 设备识别 + 攻击向量）、SD 卡探查 |
| **审计** | 带 MITRE ATT&CK 技术标签的 SQLite 审计日志、会话导出、统计 |

运行 `promptzero` 并输入 `/tools` 查看实时注册表。

<details>
<summary><b>幕后揭秘 —— agent 层</b></summary>
<br>

PromptZero 的 agent 内置了提示词缓存、按成本分级的模型路由（侦察用 Haiku，利用用 Opus）、提示词注入隔离（prompt-injection quarantine）、带结构化 `ToolError` 的错误反思（reflexion-on-error）、每回合注入的 `<device-state>` 预言机，以及 OpenTelemetry GenAI span。LLM 是一个组件，而非一个库：模型与供应商的替换都是一等公民，没有任何提示词是不可或缺的。架构细节参见 [`docs/`](docs/)。

</details>

## 运行模式

### CLI —— `promptzero`

默认模式。一个交互式 REPL。

```
promptzero> scan the SD card and show me what signals I have saved
promptzero> transmit the garage door signal
promptzero> read the NFC tag on my desk
```

斜杠命令（运行 `/help` 查看带说明的完整列表）：

- **会话对话** —— `/help`、`/reset`、`/quit`
- **会话管理** —— `/sessions`、`/save <name>`、`/resume <id>`、`/forget <id>`
- **信息** —— `/status`、`/tools [query|page <n>]`、`/history [N]`、`/audit {stats|find|tail|top|session|query|export}`、`/stats [section]`、`/cost`、`/budget [set <USD>|off]`、`/debug`
- **操作员** —— `/persona [name]`、`/mode [name]`、`/watch [pause|resume]`、`/webhooks [test <name>]`、`/validate <path>`、`/attack {set|clear} <techniques>`、`/campaign {validate|run} <file>`、`/rewind [snapshot]`、`/report [session] [json] [save]`、`/rules [list|pause|resume|test]`
- **设备** —— `/reconnect`

一个回合进行中的按键操作：

- **Ctrl+C** —— 彻底取消当前回合。
- **Ctrl+G** —— 中止当前流式传输的工具（例如 `subghz_receive`、`wifi_scan_ap`），但让 agent 带着部分结果继续。
- **Ctrl+R** —— 反向增量式历史搜索。
- **Ctrl+L** —— 清屏。

### Web UI —— `promptzero --web`

位于 `http://localhost:8080` 的深色主题浏览器界面：聊天界面、实时 Flipper 视口、文件浏览器、审计日志、报告构建器，以及 —— 当连接了 Marauder 时 —— 一块 TFT 显示面板。

> [!IMPORTANT]
> **认证。** 在配置中设置 `web.token`，或在环境变量中设置 `PROMPTZERO_WEB_TOKEN`。浏览器首次加载时会从 URL 片段中读取 `#token=…` 并将其缓存到 `sessionStorage`。空令牌 + 非回环地址绑定 → 服务器会打印一条红色警告。PromptZero 使用纯 HTTP —— 请在反向代理（Caddy / Traefik / nginx）或 Tailscale / Cloudflare 隧道处终结 TLS。

**用 Docker 托管。** 多架构镜像（`distroless`、已签名，带 SBOM + 来源证明）会在每次发布时推送到 `ghcr.io/xunholy/promptzero` —— 参见 [docs/deploy/docker.md](docs/deploy/docker.md)。

**健康探针。** `GET /healthz`（存活探针，`200 ok`）和 `GET /readyz`（就绪探针，JSON 子系统快照）无需认证，适用于无头 / systemd / k8s 部署；设备连通性会被报告但不会作为就绪的前提（Flipper/Marauder 可能在启动后才接入）。

### 语音 —— `promptzero --voice`

CLI 模式下的按键说话（push-to-talk）。不输入任何文本直接按 Enter 即可录音（需要 `sox`）；音频通过 OpenAI Whisper 转写，然后作为普通命令处理。

```
Ubuntu/Debian:  apt install sox
macOS (brew):   brew install sox
Arch:           pacman -S sox
```

### MCP —— `promptzero --mcp`

以 [Model Context Protocol](https://modelcontextprotocol.io/) 服务器身份通过 stdio 运行。添加到 Claude Desktop / Claude Code：

```json
{
  "mcpServers": {
    "promptzero": {
      "command": "/path/to/promptzero",
      "args": ["--mcp"]
    }
  }
}
```

> [!IMPORTANT]
> **MCP 风险关卡。** 风险为 High 和 Critical 的工具默认被拒绝 —— 设置 `PROMPTZERO_MCP_ALLOW_HIGH=1` 和 / 或 `PROMPTZERO_MCP_ALLOW_CRITICAL=1` 以允许它们。所有 MCP 调用（无论允许还是拒绝）都会被记入审计日志。参见下方的[安全模型](#安全模型)。

## 安全模型

PromptZero 是一款双用途的进攻性工具。其安全理念是本项目得以存在的社会许可 —— 每一个 spec 都带有一个风险等级，而该等级决定了哪些操作可自由派发、哪些必须经过确认。

<img src="https://img.shields.io/badge/Low-read--only-2f9a5a" alt="Low"> &nbsp;扫描、读取和查询 —— 自由派发。<br>
<img src="https://img.shields.io/badge/Medium-writes_%2F_emulation-c9a227" alt="Medium"> &nbsp;数据写入和信号模拟。<br>
<img src="https://img.shields.io/badge/High-TX_%2F_write_%2F_exec-e8702a" alt="High"> &nbsp;主动 RF 发射、标签写入和脚本执行 —— **需要操作员确认。**<br>
<img src="https://img.shields.io/badge/Critical-brute--force_%2F_destructive-c03030" alt="Critical"> &nbsp;暴力破解和破坏性攻击 —— **需要操作员确认。**

- **同意关卡。** High 和 Critical 工具需要操作员确认。CLI 会显示一个带框的预览（频率 / 调制 / 十六进制），并有 2 秒的延迟；肯定性的同意（`y`、`all`、`confirm`）在延迟开放之前输入会被拒绝。否定性的决定（`n`、`r` 表示修订、Esc）则绕过延迟。
- **MCP 默认拒绝。** 没有任何 MCP 客户端能在不显式通过环境变量开启的情况下运行 High 及以上的工具（见上文）。
- **审计日志故障即关闭（fail-closed）。** 如果没有初始化审计日志，agent 会拒绝 High 及以上的操作，而不是悄无声息地运行它们。
- **提示词注入隔离。** 工具输出（扫描到的 SSID、捕获的数据包、图像内容、SD 卡文件名）在被反馈回模型之前会被封装，使其无法覆盖系统提示词。
- **不自动部署生成的载荷。** BadUSB 脚本默认只部署而不执行。

请阅读 [`SECURITY.md`](SECURITY.md) 了解完整的威胁模型、范围 / 范围之外，以及如何报告漏洞。

## 兼容性

<details open>
<summary><b>固件支持</b></summary>
<br>

| 固件 | 状态 |
|---|---|
| **Momentum**（原 Xtreme） | 主要目标 |
| **Unleashed** | 支持 |
| **RogueMaster** | 支持 |
| **官方固件（OFW）1.x** | 支持，但功能集有所缩减 —— 区域锁定的 Sub-GHz、无滚动码 |

</details>

> [!NOTE]
> 官方固件将 Sub-GHz TX 锁定到特定区域的 ISM 频段，并屏蔽滚动码协议。改装固件解锁完整的 CC1101 范围（300–348 / 387–464 / 779–928 MHz），并为全部 52 个受支持协议启用 TX。

ESP32 Marauder 开发板需要固件 **v1.11.1+**，通过 USB CDC ACM 通信（官方 Flipper WiFi 开发板对应 `/dev/ttyACM1`，波特率 115200）。关于 BLE 无线（无需线缆、所有工具均可用、比 USB 慢约 10 倍）以及各平台的配对，参见 [Transports 参考](docs/reference/transports.md)。

## 文档

- [`docs/`](docs/) —— 手册，包含面向任务的场景、提示词范式和可复现的会话记录。
- [`docs/reference/tools.md`](docs/reference/tools.md) —— 一份精选的参考，涵盖**核心**工具的 schema、风险等级，以及能可靠触发它们的提示词。运行 `/tools`（或 `tool_search`）查看完整的实时注册表。
- [`docs/reference/transports.md`](docs/reference/transports.md) —— 串口、BLE、WSL2 的设置。
- [`docs/reference/configuration.md`](docs/reference/configuration.md) —— 配置文件、环境变量、人格、规则、自升级。
- [`SECURITY.md`](SECURITY.md) —— 威胁模型与披露政策。
- [`examples/`](examples/) —— 可直接复制粘贴的模板：配置、规则、四种操作员人格（red team / blue team / CTF / hardware lab）。
- [`CHANGELOG.md`](CHANGELOG.md) —— 每个版本包含的内容。

## 构建与贡献

参见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。简要版本：

```bash
git clone https://github.com/xunholy/promptzero.git
cd promptzero
task dev:setup
task build
task test
```

## 许可证

[AGPL-3.0-or-later](LICENSE)。将修改后的 PromptZero 作为网络服务托管，需要以相同的许可证发布源代码的变更。

<br>

<sub align="center">Claude 用量/成本徽章是一个估算值，由维护者本地的 Claude Code 会话记录（`task claude-usage`）聚合而来；它只反映那台机器上的会话。</sub>

<p align="center"><sub>Built with <a href="https://claude.ai">Claude</a> by <a href="https://github.com/xunholy">xunholy</a>.</sub></p>
