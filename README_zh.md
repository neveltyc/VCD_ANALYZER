<p align="center">
  <h1 align="center">VCD Analyzer</h1>
  <p align="center">
    一个单文件命令行工具，用于快速检查 Verilog <b>VCD</b> 波形。
    为 RTL 调试、AI Agent 工作流和所有不想打开波形查看器的人设计。
  </p>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/版本-1.5.1-3366cc?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9+-3366cc?style=flat-square&logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-3366cc?style=flat-square">
  <img alt="Tests" src="https://img.shields.io/badge/测试-169%20passed-22aa55?style=flat-square">
</p>

---

## 为什么需要这个工具？

仿真跑完了一个巨大的 `.vcd` 文件，你想知道 `state[3:0]` 在 17.3 us 到 17.6 us 之间发生了什么。
打开 GTKWave 意味着等 GUI 加载、点层级树、缩放波形、眯眼看数值。这个工具一条命令搞定。

它从设计之初就面向 **AI Agent 辅助调试**：每个命令都有 `--json` 模式，输出紧凑的机器可读结构，
LLM Agent 可以直接读取波形信息，无需图形界面。

```bash
python vcd_analyzer.py search sim.vcd --condition "state=5" --show data,valid --begin 17us
```

## 快速开始

```bash
# 文件里有什么？
python vcd_analyzer.py info sim.vcd

# 只看时钟和复位
python vcd_analyzer.py list sim.vcd --filter clk,rst

# 100ns 到 200ns 之间发生了什么？
python vcd_analyzer.py dump sim.vcd --begin 100ns --end 200ns --filter state

# valid=1 且 ready=1 同时成立的时刻？
python vcd_analyzer.py search sim.vcd --condition "valid=1,ready=1" --show data

# ready 为低的时候 req 在哪些时刻跳变？
python vcd_analyzer.py search sim.vcd --condition "changed(req),ready=0" --show state

# 多个通道里任意一个握手的时刻？（重复 --condition 即 OR）
python vcd_analyzer.py search sim.vcd --condition "ch0_valid=1,ch0_ready=1" \
                                      --condition "ch1_valid=1,ch1_ready=1"

# 17.55us 时刻所有信号的快照
python vcd_analyzer.py snapshot sim.vcd --at 17.55us --filter state,init_done

# 统计信号翻转次数，哪些是静态的？
python vcd_analyzer.py summary sim.vcd --filter dll_*
```

## 安装

单文件，零依赖，Python 3.9+。

```bash
# 最新版
curl -fsSL https://raw.githubusercontent.com/neveltyc/VCD_ANALYZER/main/vcd_analyzer.py -o vcd_analyzer.py

# 锁定已发布版本（推荐，避免 main 分支更新破坏兼容性）
curl -fsSL https://raw.githubusercontent.com/neveltyc/VCD_ANALYZER/v1.5.1/vcd_analyzer.py -o vcd_analyzer.py

# 验证
python vcd_analyzer.py --version
```

无需 pip、无需虚拟环境、无需 PyPI。只要有 curl 和 Python 3.9+ 就能用——适合 CI 容器、EDA 服务器、Docker 构建、Agent 工具链。

## 命令一览

| 命令 | 功能 |
|:------|:-----|
| `info` | 文件概览：时间精度、信号数量、时间跨度、层次结构 |
| `list` | 列出信号路径、位宽和类型 |
| `dump` | 按时间顺序输出时间窗口内的所有值变化 |
| `summary` | 逐信号统计：活跃/静态、变化次数、上升/下降沿 |
| `snapshot` | 指定时刻所有已知信号的瞬时值 |
| `compare` | 两个时刻之间哪些信号变了？ |
| `search` | 条件搜索：找出条件成立的区间，可选观察关联信号 |

所有命令支持 `--begin` / `--end` 时间窗口（带单位：`fs`/`ps`/`ns`/`us`/`ms`/`s`），
`--filter` 子串或通配符过滤，以及 `--json` 结构化输出。

运行 `python vcd_analyzer.py --help` 查看完整参考。

## JSON 输出

每个命令在 `--json` 下输出紧凑的结构化 JSON。Agent 和脚本可以同时获取
原始 tick 数（`_ticks`）和人类可读时间（`_h`）。

```bash
python vcd_analyzer.py --json info sim.vcd
python vcd_analyzer.py --json search sim.vcd --condition "state=5" --show data
```

## 语义说明

- **保留同一时间戳内的多次值变化。** IEEE 1364 允许同一时间戳内对同一信号写多次
  value change（delta-cycle 风格的仿真器）；`dump` 按顺序全部输出，`summary`
  逐次计数。仅仅重复断言信号当前值的记录——连续的重复值，或
  `$dumpall`/`$dumpon` 检查点重发当前值——属于 no-op，不产生变化事件
  （`summary` 的 static/active 统计保持精确）。
- **`search` 的条件是 AND 子句，重复 `--condition` 即 OR。** 一个 `--condition`
  是逗号分隔的 AND 项列表，每项是 `SIG=VAL`、`SIG!=VAL` 或 `changed(SIG)`。
  重复该标志后，任一子句成立的时刻即成立（OR-of-ANDs）——每个通道写一个子句，
  就能找出"任意通道握手"的时刻。**不支持串内 OR**：条件字符串里的 `|` 和 `OR`
  是普通文本并会被拒绝，所以误写的布尔表达式会报错，而不是给出一个看似确定的空结果。
- **`changed(SIG)` 是边沿谓词**，在 SIG 跳变的那些时刻为真，并把 `search` 切换到
  event 模式（报告时刻而非区间）。此时要么每个子句都带一个，要么都不带。
  子句里的 level 项读取该 tick 的**结算态**，所以结果不依赖同刻记录的书写顺序；
  而正在跳变的那个信号读取它**在该边沿上取到的值**，因此 `"changed(s),s=1"`
  仍然表示"s 的上升沿"。`changed(a),changed(b)` 要求两者在同一 tick 跳变。
- **条件匹配依据信号的声明类型。** real/realtime 信号按数值比较
  （`dac=3.14`、`dac=100`），绝不按位串——否则它的 `%g` 文本会被读成二进制，
  使 `dac=4` 匹配上一个值为 100.0 的 real。event 变量没有电平，
  `ev=1` 会被拒绝并指向 `changed(ev)`。
- **时间窗口。** 不给 `--end` 时，有效终点是文件最后一个时间戳，
  超出的 `--begin` 会报错。显式 `--end` 超过最后时间戳时，最后已知状态
  会延续到该窗口（与 `snapshot`/`compare` 的 last-known-value 语义一致）。

## 单文件，零依赖

`vcd_analyzer.py` 约 2400 行纯 Python。不需要 `pip install`，不需要虚拟环境
——随便放到 Python 3.9+ 环境里就能跑。

## 项目结构

```
vcd_analyzer.py       核心工具（单文件，仅依赖标准库）
verify/               pytest + unittest 测试套件 —— 52 个用例，0 失败
verify/fixtures/      脱敏 VCD 测试波形（不含任何私有路径）
verify/samples/       真实 GitHub VCD 样本，用于冒烟测试
CHANGELOG.md          简洁变更日志，含详细发行说明链接
```

## 测试

```bash
# 完整 pytest 套件（需安装 pytest）
python -m pytest verify/ -v

# 仅 unittest（标准库，无需额外安装）
python -m unittest discover -s verify -p "test_cli.py"
```

覆盖 helpers、parser 内部、命令函数、文本/JSON 输出模式、CLI subprocess、
以及三个真实外部 VCD 样本。


## Agent 技能

仓库内置了 [skill/SKILL.md](skill/SKILL.md)，专为 AI 编程 Agent 设计（Codex、Claude Code 等）。
直接从仓库安装即可 — Agent 会自动掌握全部七个命令的用法、根据任务选择正确的命令、
解析 JSON 输出，并遵循成熟的调试工作流。

技能涵盖完整命令参考、决策树、五个工作流模式、条件语法、错误恢复和环境变量调优。

## 版本历史

详细变更见 [GitHub Releases](https://github.com/neveltyc/VCD_ANALYZER/releases) 页面。快速概览见 [CHANGELOG.md](CHANGELOG.md)。

| 版本 | 亮点 |
|:------|:-----|
| `1.5.1` | 解析器保留非有限实数值(`inf`/`-inf`/`nan`,此前整条记录被静默丢弃);`summary` 的单信号 unique 集合加上限(`VCD_ANALYZER_MAX_UNIQUE_VALUES`,默认 65536,超限时以 `unique_is_exact: false` 标注下界);Ctrl-C 以 130 干净退出而非打印堆栈;stdout/stderr 强制 UTF-8 |
| `1.5.0` | `changed(SIG)` 边沿谓词取代 `--changed` 标志;`--condition` 可重复以 OR 子句;条件匹配依据信号声明类型(修复 real 信号的假阳/假阴);无法成立的条件目标改为报错而非静默无匹配;`--limit` 默认值改为 500,截断提示更清晰 |
| `1.4.0` | 内部重构:将事件流与派生状态分层为解析器的三个不同视图(`iter_events` 原始 / `iter_transitions` / `state_at` 快照);所有命令输出不变,值变化热路径略快 |
| `1.3.20` | 保留同一时间戳内的多次值变化;`info` 时间范围改用单一前向扫描器(与解析器等价,约快 1.5×,能扛超大/`$dumpall` 尾部);`search --changed` 逐次计数;`info` 的 `--limit` 校验与空数据输出 |
| `1.3.19` | 修复自由格式 VCD 正确性:一行多声明/多时间戳、静默窗口搜索、非法令牌级联、`$dumpall` 跳变计数 |
| `1.3.18` | 修复 `info` 在缩进 VCD 文件上 `time_max` 塌缩为 `time_min` 的问题 |
| `1.3.17` | $var 解析器常见形态快路径(跳过括号扫描) |
| `1.3.16` | 在值变化热路径上内联超宽钳制判断 |
| `1.3.15` | 分块数据词法分析与单行头部声明快路径 |
| `1.3.14` | dump 文本输出改为流式;新增基准测试工具 |

## 许可证

MIT —— 详见 [LICENSE](LICENSE)。&copy; 2026 neveltyc

[English](README.md)
