# logsan —— 运维日志终端控制字符注入防护

针对用户名、请求头、上传文件名等**外部输入原样写进服务日志**导致的终端
控制字符注入（CWE-117 / 日志伪造、ANSI 转义注入），提供写入、采集、查看
三层防护。纯标准库实现，无第三方依赖。

## 威胁模型

攻击者在外部字段里塞入终端控制序列，运维 `cat`/`tail`/`less` 日志时终端
会解释这些序列：

| 载荷 | 终端效果 | 危害 |
|---|---|---|
| `ESC[2J` `ESC[1;1H` | 清屏 + 光标归位 | 抹掉真实攻击记录、伪造日志行 |
| `...\r\n[OK] ...` | 回车换行 | 凭空造出一条不存在的日志行 |
| `ESC]0;title\x07` (OSC) | 改窗口标题 | 伪装终端身份 |
| `ESC]8;;url\x07` (OSC8) | 超链接注入 | 钓鱼 |
| `ESC[6n` (DSR) | 设备状态请求 | 终端**回显**，配合括号粘贴把预设命令送回命令行 |
| `ESC[200~cmdESC[201~` | 括号粘贴 | 诱导/自动执行命令 |
| `U+202E` (RLO)、零宽字符 | 视觉反转/隐藏 | 文件名欺骗、检索绕过 |

核心立场：**日志的语义是“数据”，不是“可执行的终端指令”。** 除显式白名单
（严格校验过的 SGR 颜色）外，一切控制字符都转成可见、可逆、不与正常文本
混淆的记号。

## 三层架构

```
外部输入
   │
   ▼
①写入层  SafeFormatter / SafeJSONFormatter / structlog processor
   │     格式化阶段统一清洗，输出带 _san 标记或 [SAN:] 前缀
   ▼
②采集层  collect 管道（json / syslog / plain 自动探测）
   │     递归清洗所有字符串值 → 统一 JSON 信封；多跳幂等
   ▼
③查看层  safe-cat
         遗留/第三方日志即时无害化，不改原文件，附高危告警
```

### ① 写入层（`logsan.logging_integration`）

- `SafeJSONFormatter`：标准库 `logging` 的 JSON Lines 格式化器，**逐字段
  递归清洗**并附结构化标记。推荐把外部输入通过 `extra=` 传成独立字段，
  而不是拼进 message —— 字段名保持不变，检索不受影响。
- `SafeFormatter`：包装任意现有文本 Formatter，改动最小。
- `structlog_safe_processor()`：structlog 处理器。
- 防护放在格式化阶段（拼接完成之后、落盘之前），不依赖业务代码自觉。

### ② 采集层（`logsan.collect`）

- 一个可嵌在 Filebeat/Fluent Bit/Vector/自研 agent 任意位置的纯函数管道。
- `process_line()`：自动探测格式 → 解析 → 递归清洗 → 信封化输出
  `{source, format, status, record, raw_line, _san}`。
- `iter_records()`：按花括号配对**跨行聚合**被物理拆包的 JSON 记录
  （字符串里的 `\r\n` 不会再把一条 JSON 拦腰截断）。
- 解析失败回退 plain，**绝不丢行**；非法 UTF-8 用 surrogateescape 无损保留。
- **幂等**：已带 `_san.sanitized` 的 JSON 记录或带 `[SAN:]` 前缀的文本行，
  二跳只做信封化、不再转义，记号不会被二次编码。

### ③ 查看层（`logsan.view` / `safe-cat`）

写入层和采集层只能保护上线后的新日志；磁盘上的历史日志、来不及改造的
第三方组件日志仍可能带毒。`safe-cat` 在打印前即时清洗：

- 物理行只按 `\n` 切分，孤立 `\r` 作为行内数据转义，不让伪造文字另起一行；
- 对每条转义序列给出 `high/medium/info` 分级（清屏、光标定位、DSR 回显
  为 high）；
- 只读，不修改原文件；`--fail-on-high-risk` 可接入巡检。

## 关键设计决策

### 1. 可逆编码，且默认记号对检索友好

`BackslashXEncoder`（默认）：C0/DEL → `\xNN`，其余 → `\uNNNN`。记号全是
可见 ASCII，grep/awk/ES/Loki 的分词与子串匹配行为与普通文本一致；
`decode` 可在取证时还原攻击者原始 payload。另有 `ControlPictureEncoder`
把 C0 映射到 `␛␊` 等控制图片字符，更直观，适合直接展示。

### 2. 颜色与多语言不是非黑即白

- 多语言（中日韩、阿拉伯文等）是普通可打印字符，**原样保留**。
- 合法颜色日志通过 `Policy(allow_sgr=True)` 放行，但 SGR 必须通过**严格
  白名单**：只接受 `ESC[` + 数字/分号 + `m`，长度受限。`ESC[2J`（清屏）、
  `ESC[?25l`（私有模式）即使开了开关也一律拒绝。
- 外部输入字段不应开 `allow_sgr`；该开关只给受信的内部服务日志。

### 3. 转义不破坏既有检索与告警

- 普通可见字符串的检索**完全不受影响**（转义只动控制字符）。
- 含控制字符的旧 IDS 特征，用 `query.encode_search_term()` 编码后再匹配。
- 迁移期用 `query.migration_pattern()` 生成“原始 + 转义”双形态正则，
  同时覆盖历史日志与新日志。
- 告警规则只依赖**稳定的标记字段** `_san.sanitized`，与具体转义记号解耦，
  更换编码器不需要改规则：

  ```
  Lucene:  _san.sanitized: true
  ES DSL:  {"bool": {"filter": [{"term": {"_san.sanitized": true}}]}}
  grep:    grep -E '\[SAN:escaped\]|"_san":\{"sanitized":true'
  ```

### 4. 幂等是链路安全的前提

采集链路组件多、可能多跳处理。编码器只产生可见 ASCII（再次清洗不会被
二次转义），配合 `_san` 标记 / `[SAN:]` 前缀的显式识别，保证一条记录
无论经过几跳，记号形态稳定、标记不丢失。

## 命令行用法

```bash
# 安全查看遗留日志（不改原文件，stderr 出告警报告）
python -m logsan safe-cat /var/log/auth.log

# 采集管道：每行输出一个统一 JSON 信封
python -m logsan collect -f app.jsonl --source api-gateway --format auto

# 直接清洗
printf '\033[2J' | python -m logsan sanitize

# 检索特征编码 / 迁移期 grep 双形态正则
python -m logsan search "$(printf 'a\r\nb')" --grep

# 取证：还原转义记号为原始 payload
python -m logsan decode 'mallory\x1b[2J'
```

## 代码接入

```python
import logging
from logsan.logging_integration import SafeJSONFormatter

handler = logging.StreamHandler()
handler.setFormatter(SafeJSONFormatter())
logging.getLogger().addHandler(handler)

# 外部输入作为独立字段传入，字段名不变、可正常检索
logger.info("upload", extra={"user": user, "upload_name": filename})
```

## 测试

```bash
python3 -I -m unittest discover -s tests -t .
```

46 个用例覆盖：清屏/光标/OSC/DSR/括号粘贴等攻击向量、CRLF 日志伪造、
严格 SGR 白名单与绕过、bidi/零宽字符、幂等（含多跳采集）、可逆性、
多语言、多格式解析、跨行 JSON 聚合、非法 UTF-8、检索兼容与端到端链路。

## 模块一览

| 模块 | 职责 |
|---|---|
| `policy.py` | 字符分类、`Policy` 策略、核心 `sanitize()` |
| `ansi.py` | 严格 SGR 校验、危险序列识别与分级 |
| `encoding.py` | 可逆编码器（反斜杠记号 / 控制图片） |
| `marking.py` | `_san` 标记与 `[SAN:]` 前缀的统一约定 |
| `logging_integration.py` | 写入层：logging / structlog 集成 |
| `collect.py` | 采集层：多格式解析、递归清洗、信封化、跨行聚合 |
| `view.py` | 查看层：安全渲染与告警报告 |
| `query.py` | 检索特征编码、迁移期正则、告警规则模板 |
| `cli.py` | `sanitize / collect / safe-cat / search / decode` 子命令 |
