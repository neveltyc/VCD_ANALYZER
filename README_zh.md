<p align="center">
  <h1 align="center">VCD Analyzer</h1>
  <p align="center">
    一个单文件命令行工具，用于快速检查 Verilog <b>VCD</b> 波形。
    为 RTL 调试、AI Agent 工作流和所有不想打开波形查看器的人设计。
  </p>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/版本-1.3.9-3366cc?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9+-3366cc?style=flat-square&logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-3366cc?style=flat-square">
  <img alt="Tests" src="https://img.shields.io/badge/测试-41/41%20通过-22aa55?style=flat-square">
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

# 17.55us 时刻所有信号的快照
python vcd_analyzer.py snapshot sim.vcd --at 17.55us --filter state,init_done

# 统计信号翻转次数，哪些是静态的？
python vcd_analyzer.py summary sim.vcd --filter dll_*
```

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

## 单文件，零依赖

`vcd_analyzer.py` 约 2400 行纯 Python。不需要 `pip install`，不需要虚拟环境
——随便放到 Python 3.9+ 环境里就能跑。

## 项目结构

```
vcd_analyzer.py       核心工具（单文件，仅依赖标准库）
verify/               pytest + unittest 测试套件 —— 41 个用例，0 失败
verify/fixtures/      脱敏 VCD 测试波形（不含任何私有路径）
verify/samples/       真实 GitHub VCD 样本，用于冒烟测试
version_notes/        每个版本的变更说明（33 个版本）
archive/              所有已发布版本的快照
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

## 版本历史

详细变更见 [version_notes/](version_notes/)。

| 版本 | 亮点 |
|:------|:-----|
| `1.3.9` | 消除数据扫描路径中的重复解析代码 |
| `1.3.8` | 加固输入校验和错误报告 |
| `1.3.7` | 修复字面量总线范围通配和转义标识符作用域 |
| `1.3.0` | 基于条件和观察信号重新设计搜索 |
| `1.0.0` | 首次公开发布 |

## 许可证

MIT —— 详见 [LICENSE](LICENSE)。&copy; 2026 neveltyc

[English](README.md)

