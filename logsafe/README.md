# logsafe — 运维日志终端控制字符注入防御

外部输入（用户名、请求头、上传文件名、URL、邮件地址……）被原样写进服务日志，
攻击者在其中塞入终端控制序列后，运维人员在终端里 `cat`/`tail`/`less` 日志时：

- **屏幕被改写**：`ESC[2K`（清行）、`ESC[1G`（光标回行首）配合 `\r` 伪造出
  不存在的"成功"日志行，覆盖真实的攻击记录；
- **内容被隐藏**：`ESC[2J` 清屏、`U+202E` 反向覆盖字符（`invoice‮txt.exe`
  在终端里显示成 `exe.txt‮ecniovi` 之类的反向文本）、零宽字符切断检索词；
- **命令被送回 shell**：`ESC[?2004h`（bracketed paste）、DCS/OSC 等序列在部分
  终端里能让攻击者预设的文字进入命令行输入缓冲区，诱导回车执行。

本项目用纯标准库 Python 在**写入、采集、查看**三个环节做纵深防御，零依赖、
可独立部署、全程幂等，并保证已有告警规则与检索语句继续可用。

## 三层架构

```
外部输入 ──► ① 写入层            ② 采集层              ③ 查看层
            logging Filter      流处理 / JSONL         安全查看器
            SafeJSONFormatter   logsafe-collect        logsafe-view
            （应用进程内）       （采集 agent/边车）    （运维终端，最后防线）
```

任一层被绕过，其余层仍能兜底。

### ① 写入层 `logsafe.logging_ext`

- `SanitizingFilter`：挂在现有 handler 上，在格式化**之前**净化 `record.args`
  （`%s` 模板的实际值）和所有 `extra=` 字段，兼容你现有的 formatter/格式串。
- `SafeJSONFormatter`：直接输出 JSON Lines，逐字段净化并写入
  `logsafe_injection` / `logsafe_ctrl_count` / `marker` 三个附加字段。
- 只处理**数据层字符串**；格式串、logger 名等应用自控内容不动。

```python
import logging
from logsafe.logging_ext import SanitizingFilter, SafeJSONFormatter

handler = logging.StreamHandler()
handler.setFormatter(SafeJSONFormatter())     # 或保留原 formatter，只加 filter：
handler.addFilter(SanitizingFilter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
```

### ② 采集层 `logsafe.collect`（CLI: `logsafe-collect`）

面向采集链路上格式各异的组件，按**行**处理：

- 行内的 `\r`/`\n` 一律净化（防日志分行伪造），传输用的行尾分隔符保留；
- JSONL 模式先解析结构再逐字段净化，**键原样保留**，所以字段级告警/检索不受影响；
  用 `json.loads(strict=False)` 容忍字符串里未转义的裸控制字节（真实环境常态）；
- 非法 UTF-8 解码成可见的 `\xff` 文本并计数，绝不崩溃或静默替换；
- `--envelope` 可把可疑行整体包进信封而不改写原文，满足合规留痕要求；
- **幂等**：多组件重复处理时输出字节完全一致，标记永不翻转。

```bash
python -m logsafe.collect --jsonl --mark-prefix < /var/log/app.log > safe.jsonl
python -m logsafe.collect --envelope            < raw.log        > enveloped.log
```

### ③ 查看层 `logsafe.viewer`（CLI: `logsafe-view`）

最后一道防线，**保证永不向终端写出任何活跃控制序列**（刻意不提供"原始模式"）：

```bash
python -m logsafe.viewer /var/log/app.log              # hex 标记，可疑行加 !! 前缀
python -m logsafe.viewer --mode caret  app.log         # ^[ ^M 经典写法
python -m logsafe.viewer --highlight    app.log         # 高亮净化后的 token
python -m logsafe.viewer --stats        app.log         # 只看攻击分类统计
```

## 转义模式与策略（`logsafe.sanitize.Policy`）

| 模式 | 效果 | 适用 |
|---|---|---|
| `hex`（默认） | `ESC[2J` → `<CSI 0x1B 0x5B 0x32 0x4A>`，`\r` → `<0x0D>` | 可读性最好，幂等 |
| `caret` | `ESC` → `^[`，`\r` → `^M` | 运维熟悉的经典写法，幂等 |
| `strip` | 直接删除控制字节 | 空间敏感场景 |
| `replace` | 每序列一个 `<CSI>`/`<CTRL>` | 仅看有无、不看内容 |

关键策略项：

- `allow_sgr=True`：**保留合法颜色序列**（标准 `ESC[..m`），但光标移动、清屏、
  私有模式（`?`/`>`/`=` 前缀，如 bracketed paste）、OSC/DCS 无论如何都净化；
  JSON 输出里颜色一律不保留（机器消费无需颜色）。
- `cf_policy`：默认 `dangerous` 只净化有攻击意义的 Unicode 格式字符
  （bidi 覆盖 `U+202A..202E/2066..2069`、零宽空格 `U+200B`、BOM、tag 字符等），
  **刻意保留 ZWJ `U+200D`**，使 emoji 组合和印地语/阿拉伯语等多语言文本不受影响；
  设 `all` 净化全部 Cf，设 `keep` 全部保留。
- 所有非控制字符（含中日韩、emoji、重音字母）原样保留。

## 告警规则与检索如何继续可用（`logsafe.search`）

- **结构化（JSON）日志**：字段键不变、字段值的可见内容不变，只是注入的控制字节
  被编码。原有 `user: "admin"`、`status: 500` 这类字段查询完全不受影响；新增的
  `logsafe_injection=true` 可直接作为高优告警条件（ES/Splunk/LogQL 样例见模块）。
- **文本日志的旧规则**：用 `search.escape_variants(规则串)` 自动生成该规则在
  原始/hex/caret 三种形态下的检索词，用 OR 连接；`build_regex()` 给出一条同时
  匹配三种形态的正则；`detector_rule_pcre()` 给出通用注入检测 PCRE。
- 固定标记 `[LOGSAFE-INJECTION]` 是稳定字符串，可直接 `grep -F`。

## 设计要点

1. **可审计的解析器**（`controls.py`）：手写小型 ESC 序列状态机，区分 CSI/OSC/DCS/
   单字节 ESC；截断序列只消费孤立 ESC，绝不会吞掉后续日志内容；OSC/DCS 到行尾
   无终止符时消费到末尾，永不挂起。
2. **无损可追溯**：默认模式下每个被处理的字节都变成可见文本，攻击证据完整保留
   （伪造的"成功"行和真实的失败行会同时出现在净化结果里），而非静默删除。
3. **幂等**：hex/caret/strip/repeat 四种模式输出再处理都不变，这是多组件采集链路
   安全的前提。
4. **零依赖**：仅用标准库，Python ≥ 3.9；测试用 `unittest`，53 个用例。

## 测试与演示

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python examples/demo.py
```

## 落地建议

- 写入层优先上 `SafeJSONFormatter`，从源头让日志成为结构化、自带标记的数据；
- 采集 agent 统一用 `logsafe-collect --jsonl`，对不支持改造的遗留服务用纯文本模式兜底；
- 运维跳板机把 `cat`/`tail`/`less` 包一层别名指向 `logsafe-view`，作为最后防线；
- 告警平台新增 `logsafe_injection=true` 规则，并对 `categories` 里出现 `dcs`/
  `invalid_utf8` 的情况提级（这两类在正常业务里几乎不应出现）。
