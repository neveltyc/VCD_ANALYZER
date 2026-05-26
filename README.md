<p align="center">
  <h1 align="center">VCD Analyzer</h1>
  <p align="center">
    A fast, single-file CLI for inspecting Verilog <b>VCD</b> waveforms &mdash;
    built for RTL debug, agent workflows, and anyone who wants answers without opening a waveform viewer.
  </p>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.3.9-3366cc?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9+-3366cc?style=flat-square&logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-3366cc?style=flat-square">
  <img alt="Tests" src="https://img.shields.io/badge/tests-41/41%20passed-22aa55?style=flat-square">
</p>

---

## Why VCD Analyzer?

You have a giant `.vcd` dump from simulation and you need to know what happened to `state[3:0]`
between 17.3 us and 17.6 us. Opening GTKWave means waiting for the GUI, clicking through the
hierarchy, zooming in, squinting at values. This tool gives you the answer in one command.

It is also designed from the ground up for **agent-assisted workflows**: every command has a
`--json` mode that emits compact, machine-readable output so LLM agents can inspect waveforms
without a GUI.

```bash
python vcd_analyzer.py search sim.vcd --condition "state=5" --show data,valid --begin 17us
```

## Quick start

```bash
# What's in this file?
python vcd_analyzer.py info sim.vcd

# Show me the clock and reset
python vcd_analyzer.py list sim.vcd --filter clk,rst

# What happened between 100 ns and 200 ns?
python vcd_analyzer.py dump sim.vcd --begin 100ns --end 200ns --filter state

# When was valid=1 AND ready=1 at the same time?
python vcd_analyzer.py search sim.vcd --condition "valid=1,ready=1" --show data

# Give me a snapshot at exactly 17.55 us
python vcd_analyzer.py snapshot sim.vcd --at 17.55us --filter state,init_done

# Any signal change count, static vs active?
python vcd_analyzer.py summary sim.vcd --filter dll_*
```

## Commands

| Command | What it does |
|:--------|:-------------|
| `info` | Timescale, signal count, time span, scopes &mdash; the file at a glance |
| `list` | Enumerate signals with path, width, and type |
| `dump` | Print every value change in a time window, in order |
| `summary` | Per-signal stats: active/static, change count, rise/fall edges |
| `snapshot` | What are all known signal values at time T? |
| `compare` | What changed between T1 and T2? |
| `search` | Find intervals where conditions hold, optionally watching related signals |

All commands accept `--begin` / `--end` time windows with unit suffixes (`fs`, `ps`, `ns`, `us`, `ms`, `s`),
`--filter` with substring or glob patterns, and `--json` for structured output.

Run `python vcd_analyzer.py --help` for the full reference.

## JSON output

Every command emits compact structured JSON under `--json`. Agents and scripts
get raw tick counts (`_ticks`) alongside human-readable times (`_h`).

```bash
python vcd_analyzer.py --json info sim.vcd
python vcd_analyzer.py --json search sim.vcd --condition "state=5" --show data
```

## Single file, zero dependencies

`vcd_analyzer.py` is ~2,400 lines of pure Python. No pip install, no virtualenv
ritual &mdash; drop it anywhere with Python 3.9+ and it works.

## Project layout

```
vcd_analyzer.py       The tool (single file, stdlib only)
verify/               pytest + unittest suite — 41 tests, 0 failures
verify/fixtures/      Sanitized VCD waveforms (no private paths)
verify/samples/       Real-world GitHub VCD fixtures for smoke testing
version_notes/        Per-release change logs (33 releases)
archive/              Snapshots of every published version
```

## Tests

```bash
# Full pytest suite (requires pytest)
python -m pytest verify/ -v

# unittest only (stdlib, no extra installs)
python -m unittest discover -s verify -p "test_cli.py"
```

Covers helpers, parser internals, command functions, text/JSON modes, CLI
subprocess smoke, and three external real-world VCD samples.

## Version history

Full per-version notes live in [version_notes/](version_notes/).

| Version | Highlight |
|:--------|:----------|
| `1.3.9` | Eliminate duplicated value-change parsing |
| `1.3.8` | Harden input validation &amp; error reporting |
| `1.3.7` | Literal bus-range globs &amp; escaped-scope reporting |
| `1.3.0` | Redesign search around conditions &amp; observations |
| `1.0.0` | Initial public release |

## License

MIT &mdash; see [LICENSE](LICENSE). &copy; 2026 neveltyc

[中文说明](README_zh.md)

