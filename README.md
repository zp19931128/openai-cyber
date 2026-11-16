# OpenAI Cyber · CPR 关键词门禁

内置中英文 Cyber 与通用滥用规则，并通过独立配置补充关键词、正则和组合规则。无需审核 API、GPU 或额外数据库。CPR 适配入口在 [`plugin/`](plugin/)，离线工具和匹配引擎位于项目根目录。

## 规则与适用范围

[`rules/builtin.json`](rules/builtin.json) 含 70 条规则、646 个词组备选项，覆盖 Cyber、通用滥用和恶意越狱共 16 类风险：凭据与会话窃取、钓鱼、勒索、未授权访问、撞库盗号、拒绝服务、恶意持久化、恶意规避检测、数据外传、诈骗、暴力伤害、非法武器、危险物质、隐私侵害、儿童性剥削抽象类别，以及绕过模型安全限制执行有害请求。

同一规则的 `all_groups` 必须全部命中，每组命中任意一个词组即可；命中须位于同一句且不超过 `max_span_chars` 个 Unicode 字符。英文内置规则检查单词边界。匹配前统一 Unicode NFKC、大小写，并移除指定的零宽字符。

“漏洞、扫描、木马、EDR、CTF”等词不会单独导致拒绝，也不因出现“研究、授权、教育”而全局放行。完整恶意指令即使出现在引用或取证材料中，也可能命中；规则无法理解否定、授权真实性或多轮语义。

越狱规则要求同时出现明确的安全绕过指令与有害／违法执行目标，覆盖关闭安全限制、无约束角色、制作恶意越狱提示、编码后跳过审核和抑制拒绝。不会单独封禁“破甲、DAN、角色扮演、开发者模式”或正常的格式修改指令。组合仅在同句 180 字符内匹配；分句、改写或编码可能漏检，任意编码载荷不会被自动解码。

**未命中只表示没有触发词库，不表示符合全部 OpenAI 政策。** 此版本仅面向文本关键词检查，不提供图片、音频、任意编码解码或完整政策分类。通用滥用词库仅涵盖列出的类别，不构成法律或政策合规保证。

## CPR 插件

插件使用官方公开 SDK，绑定 `request` 中间件，在 HTTP JSON、SSE 和 WS 每轮逻辑模型请求进入选路与上游发送前检查。适用格式为 OpenAI；不挂载管理后台。创建插件实例后必须设置并启用 `request` 绑定，故障策略选择拒绝，不能选择委托下游。

每轮检查 JSON 中的字符串值，先解码 JSON 转义；同一消息相邻的文本块还会拼接检查。命中或无法检查时不调用 `next`，返回 SDK `Rejected`，发送状态为 `NotSent`。未命中时直接调用原始 `next`，不改写提示词、请求头、响应正文或流式协议。

本轮包含的系统指令、工具定义、工具结果和引用材料也可能触发规则。插件不恢复 `previous_response_id` 指向的历史、不读取远程文件或图像，也不拼接不同消息；不能宣称识别跨轮拆分的意图。原始 JSON 请求上限 2 MiB，超过上限或解析失败直接拒绝。

拒绝时调用宿主的有界日志服务，只发送请求 ID、规则 ID、类别和词库版本；日志可能被宿主限流、过滤或丢弃，不作为完整审计账本。错误不回显原始提示词或命中片段。

清单将宿主范围限定为 `>=3.39.1, <=3.48.0`，已静态核对 3.39.1、3.40.0 和 3.48.0 的 manifest v2 / RPC v7 / middleware v6 合同；3.48.0 的 SDK 请求接口与构建所用提交一致。真实安装、绑定、WS 错误交付和流式透传须在目标宿主验收，编译与打包成功不代表线上已生效。安装插件意味着信任其全部代码，宿主不提供 OS 沙箱。

插件配置采用下面相同的 JSON；保存配置后由宿主发布新的不可变会话，规则按会话编译一次。没有独立词库管理页面。

## 通过 GitHub 安装

在 CPR 的“插件管理 → 安装 → GitHub”填写：

| 项目 | 值 |
| --- | --- |
| 仓库 | `zp19931128/openai-cyber` |
| 标签 | `v0.1.1`，或留空查询最新稳定 Release |
| 安装附件 | `wason.keyword-guard-0.1.1-x86_64-unknown-linux-gnu.tar.gz` |
| 适用环境 | Linux x86_64，CPR `3.39.1` 至 `3.48.0` |

GitHub 安装读取 [Release 附件](https://github.com/zp19931128/openai-cyber/releases)，不从源码编译。自动生成的 Source code 归档不能安装。核对包摘要和版本后接受来源；首次安装会由 CPR 生成默认配置与绑定，核对 `request` 挂载已启用、作用范围正确、失败策略为拒绝。先在测试实例验证普通请求与拦截请求，再接入生产流量。

仅此平台提供二进制，其他平台不能通过修改文件名安装。超出声明宿主范围时应先验证 SDK 合同，不能直接忽略兼容提示。下载遇到 GitHub API 限流时，可配置自己的下载认证，或从同一 Release 下载附件后使用“上传包”。

## 补充规则

复制 [`config/custom.example.json`](config/custom.example.json) 为自己的配置文件，三个补充入口可同时使用：

```json
{
  "schema_version": 1,
  "disabled_builtin_ids": [],
  "extra_keywords": ["你自己指定的拒绝短语"],
  "extra_regexes": ["(?i)your\\s+blocked\\s+phrase"],
  "custom_rules": [
    {
      "id": "custom.example",
      "category": "custom",
      "description": "多个条件同时命中才拒绝",
      "all_groups": [["条件一", "条件一的替代短语"], ["条件二"]],
      "max_span_chars": 120,
      "word_boundaries": false
    }
  ]
}
```

`extra_keywords` 是直接子串拒绝，包含一个高频词就可能大量误伤，建议填写明确短语。`extra_regexes` 在规范化后的单句上匹配，使用 Rust regex 语法，不支持回溯引用或环视。跨句的字面短语会在加载时拒绝。补充规则不修改内置文件；同名 ID、未知禁用 ID、无效正则或过大的规则集会报错，不静默替换或清空规则。

使用 `disabled_builtin_ids` 按 ID 停用指定内置规则。升级内置词库前保留自己的配置文件；词库更新不能覆盖补充内容。

## 离线校验

```sh
cargo run --release -- validate --config config/custom.example.json
cargo run --release -- check --config config/custom.example.json < prompt.txt
cargo run --release -- export > builtin-export.json
```

`check` 从标准输入读取纯 UTF-8 文本，最多 2 MiB，超限报错，不只扫描前缀。退出码：`0` 未命中，`2` 拒绝，`1` 配置或检查失败。JSON 输出只含判定、规则 ID、类别和词库版本，不回显原始提示词或命中片段。标准输出属于本地命令行工具；CPR 插件的 stdout 仅用于 SDK 协议。

## 检查

```sh
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

[`tests/corpus.json`](tests/corpus.json) 包含 145 条中英文语料，用于验证恶意指令、正常开发、防御分析、越狱识别、跨句和引用边界。样例通过不代表零误报或零漏报。

## 构建插件与安装包

插件要求 Rust 1.99.1；SDK 依赖固定至已存在的 Git commit，根目录离线工具支持 Rust 1.93。

```sh
cargo build --manifest-path plugin/Cargo.toml --release --locked --target x86_64-unknown-linux-gnu
cargo fmt --manifest-path plugin/Cargo.toml -- --check
cargo clippy --manifest-path plugin/Cargo.toml --all-targets --locked -- -D warnings
cargo build --manifest-path plugin/Cargo.toml --locked
python3 scripts/verify-plugin.py plugin/target/debug/cpr-keyword-guard-plugin
```

Linux 二进制须在 Linux 环境构建或使用完整交叉工具链，不能给 macOS 二进制换一个 target 名称。使用与 SDK 同一提交构建的官方 [`cpr-plugin`](https://github.com/zyycn/codex-proxy-rs/tree/5b7f307bb26a5d0221f1f59475bc049bb350c21a/backend/apps/plugin-cli) 打包：

```sh
cpr-plugin package \
  --manifest plugin/plugin.json \
  --binary plugin/target/x86_64-unknown-linux-gnu/release/cpr-keyword-guard-plugin \
  --target x86_64-unknown-linux-gnu \
  --output-dir dist
```

`dist/` 产出 `.tar.gz` 和 `.sha256`，上传前核对摘要、宿主版本和目标平台。补充配置独立于安装包；词库内置在二进制中，更新内置词库后需重新构建。

GitHub Actions 在推送 `main` 时执行检查与打包；推送与包版本一致的 `v` 标签时，使用仓库内置的 `GITHUB_TOKEN` 发布稳定 Release 和安装附件。仅发布步骤有 `contents: write`，不需要添加个人 token。发布在全部检查、Linux 构建、RPC 校验和官方打包成功后执行。
