---
name: vcd-waveform-debug
description: VCD waveform analysis for RTL debug. Use when the user has a .vcd file and wants to inspect, search, compare, or summarize digital simulation waveforms. Triggers include any mention of VCD files, waveform analysis, signal dump inspection, RTL debug, simulation results, value change dump, or specific VCD signal queries like "what is the value of X at time Y", "when does valid go high", "compare state at T1 vs T2", "find all AXI handshakes". Also triggers when the user uploads a .vcd file or references one by path. Do NOT use for FSDB, SHM, WLF, or other proprietary waveform formats — those require vendor tools to convert to VCD first.
---

# VCD Waveform Analyzer — Agent Skill

## What this tool does

`vcd_analyzer.py` is a single-file, zero-dependency Python CLI that parses IEEE 1364 VCD files and exposes seven query commands. It reads VCD files in streaming mode (constant memory regardless of file size), handles QuestaSim bit-exploded buses, Extended VCD port states, and malformed/hostile inputs safely.

All commands support `--json` for structured output. **Always use `--json` when calling from an agent.**

## Setup (one-time)

```bash
curl -fsSL https://raw.githubusercontent.com/neveltyc/VCD_ANALYZER/v1.3.12/vcd_analyzer.py -o vcd_analyzer.py
python3 vcd_analyzer.py --version   # expect: vcd_analyzer 1.3.12
```

No pip install, no virtualenv, no dependencies. Python 3.9+.

## Decision tree: which command to use

```
User wants to know...
├─ "What's in this VCD file?"
│   └─ info           → file overview, signal count, time span, scopes
├─ "What signals exist?" / "Find signals matching X"
│   └─ list           → signal paths with width and type
├─ "What happened between T1 and T2?"
│   └─ dump           → raw value-change events in time order
├─ "Which signals are active/static?"
│   └─ summary        → per-signal change count, rise/fall edges, unique values
├─ "What is the value of X at time T?"
│   └─ snapshot       → all known signal values at one time point
├─ "What changed between T1 and T2?"
│   └─ compare        → diff of signal values at two time points
├─ "When does condition C hold?" / "Find handshakes" / "Find state=X"
│   └─ search         → condition-based search with three sub-modes:
│       ├─ interval   → time ranges where condition is true (no --show)
│       ├─ segment    → intervals + observed signal values (with --show)
│       └─ event      → per-change snapshots (with --changed)
```

## Command reference

### Universal options (apply to every command)

| Option | Effect |
|---|---|
| `--json` | **Always use this.** Compact JSON to stdout. |
| `--limit N` | Max results. Default 200. `--limit 0` = unlimited. |
| `--verbose` | Extra fields (width, type, raw values). Disables default limit. |

### Time argument format

Bare integer = raw VCD ticks. With unit suffix = converted using the file's `$timescale`.

Valid: `0`, `100ns`, `17.5us`, `1ms`, `500ps`, `200fs`, `.5ns`
Invalid: `10.5` (ambiguous — use `10.5ns`), `5 ns` (no space allowed)

### Filter pattern format (`--filter`)

Comma-separated. Plain text = case-insensitive substring match. `*` and `?` = glob (but `[` is literal, safe for bus ranges like `data[7:0]`).

```
--filter clk,rst                       # substring: matches tb.clk, tb.rst_n
--filter '*_valid,*_ready'             # glob: matches any signal ending in _valid or _ready
--filter 'top.u_dma.*'                # glob: all signals under top.u_dma scope
```

---

### 1. info — file overview

```bash
python3 vcd_analyzer.py --json info <file>
```

Key JSON fields: `signal_count`, `time_min_ticks`, `time_max_ticks`, `duration_h`, `timescale`, `scopes[]`, `version` (simulator ID), `var_types` (wire/reg/real counts), `synthesized_buses` (auto-reassembled bit-exploded buses).

**Use first on any new VCD file** to learn the time range, signal count, scope hierarchy, and timescale before issuing further commands.

### 2. list — find signals

```bash
python3 vcd_analyzer.py --json list <file> [--filter K1,K2]
```

Key JSON fields: `signals[].path`, `signals[].width`, `signals[].type`.

Signal paths use dot-separated scope hierarchy: `tb.u_cpu.u_alu.result[31:0]`.

### 3. dump — raw value changes

```bash
python3 vcd_analyzer.py --json dump <file> [--begin T] [--end T] [--filter K1,K2]
```

Key JSON fields: `events[].time_ticks`, `events[].time_h`, `events[].path`, `events[].value`.

Values are formatted: scalars as `0`/`1`/`x`/`z`, vectors as `decimal (0xhex)`, 4-state vectors as `b01xz`, reals as float strings, events as `triggered`.

**Always provide `--begin` and `--end`** to avoid dumping the entire file. **Always provide `--filter`** to avoid flooding output with every signal.

### 4. summary — signal activity overview

```bash
python3 vcd_analyzer.py --json summary <file> [--begin T] [--end T] [--filter K1,K2]
```

Key JSON fields: `rows[].path`, `rows[].kind` (`active`/`static`), `rows[].changes`, `rows[].rise_count`/`fall_count` (1-bit signals only), `rows[].init`, `rows[].last`, `rows[].unique`.

Use to quickly identify which signals are toggling in a time window and which are stuck.

### 5. snapshot — signal values at a point

```bash
python3 vcd_analyzer.py --json snapshot <file> --at T [--filter K1,K2]
```

Key JSON fields: `signals[].path`, `signals[].value`. Also `known` (how many have values) and `undefined` (selected but never assigned).

### 6. compare — diff between two times

```bash
python3 vcd_analyzer.py --json compare <file> --at T1,T2 [--filter K1,K2]
```

Key JSON fields: `diffs[].path`, `diffs[].at_t1`, `diffs[].at_t2`. Only signals whose value differs are included.

### 7. search — condition-based query (three modes)

This is the most powerful command. Mode is selected by which options are present:

#### Interval mode (no `--show`, no `--changed`)

"When is the condition true?"

```bash
python3 vcd_analyzer.py --json search <file> --condition "state=5" [--begin T] [--end T]
python3 vcd_analyzer.py --json search <file> --condition "valid=1,ready=1" [--begin T] [--end T]
```

Returns `intervals[]` with `begin_ticks`, `begin_h`, `end_ticks`, `end_h`.

#### Segment mode (with `--show`)

"When is the condition true, and what are the observed signal values during each sub-interval?"

```bash
python3 vcd_analyzer.py --json search <file> --condition "arvalid=1,arready=1" --show araddr,arlen,arid
```

Returns `segments[]` with `begin_h`, `end_h`, `values: {path: formatted_value}`. A new segment starts whenever any `--show` signal changes value while the condition remains true.

**This is the primary tool for protocol transaction extraction** — e.g., capturing every AXI handshake with its address and length.

**Important:** the JSON output key differs by mode — `intervals` (no `--show`/`--changed`), `segments` (with `--show`), `events` (with `--changed`). Always check the `mode` field.

#### Event mode (with `--changed`)

"Show me a snapshot each time a specific signal changes, while the condition holds."

```bash
python3 vcd_analyzer.py --json search <file> --changed data_out --condition "valid=1" --show data_out,valid
```

Returns `events[]` with `time_ticks`, `time_h`, `values: {path: formatted_value}`.

Each event fires when the `--changed` signal genuinely transitions (not initial assignment, not same-value re-dump). If `--show` is omitted, the changed signal itself becomes the show list.

### Condition syntax

Comma-separated AND list. Each item: `SIGNAL=VALUE`, `SIGNAL==VALUE`, or `SIGNAL!=VALUE`.

- Signal pattern must match **exactly one** signal (use `list` first to find the right path).
- Values: decimal (`5`, `255`), hex (`0xff`), binary (`b1010`, `0b1010`), 4-state (`b1x0z`), or the literal `x`/`z`.
- `!=` does **not** match `x`/`z`/undefined. Unknown is not evidence of difference. To find unknowns, use `signal=x`.
- No OR operator. To search for `state=3 OR state=5`, run two searches and merge results.

---

## Workflow patterns

### Pattern 1: First contact with a VCD file

```
1. info           → learn time range, signal count, scopes, timescale
2. list           → find signals of interest (use --filter to narrow)
3. summary        → identify active vs static signals in the relevant window
4. dump or search → drill into specifics
```

### Pattern 2: "What happened at time T?"

```
1. snapshot --at T                          → see all values at that moment
2. dump --begin T-delta --end T+delta       → see what changed around T
3. compare --at T-delta,T+delta             → diff view of the window
```

### Pattern 3: Protocol transaction extraction (e.g., AXI)

```
1. list --filter '*valid,*ready,*addr,*data,*len'   → find channel signals
2. search --condition "arvalid=1,arready=1" --show araddr,arlen
   → extract all read-address handshakes with address and burst length
3. search --condition "wvalid=1,wready=1" --show wdata,wstrb
   → extract all write-data beats
```

### Pattern 4: Find when a signal enters an unexpected state

```
1. search --condition "state=x"             → find when state goes unknown
2. search --condition "error!=0"            → find when error is asserted (excludes x/z)
3. snapshot --at <first_hit_time>           → see full system state at that moment
4. dump --begin <before_hit> --end <first_hit> --filter relevant_signals
   → trace what led to the bad state
```

### Pattern 5: Clock and reset sanity check

```
1. summary --filter clk,rst,reset          → check toggle counts and rise/fall edges
   → clk should be active with balanced rise/fall
   → rst should be static after initial assertion
```

---

## Environment variables

For exceptionally large VCD files, tune resource limits:

| Variable | Default | Effect |
|---|---|---|
| `VCD_ANALYZER_MAX_VARS` | 1,000,000 | Max `$var` declarations |
| `VCD_ANALYZER_MAX_REASSEMBLE_BITS` | 65,536 | Max bits per bit-exploded bus |

Increase if the tool reports `too many $var declarations` or `bit-exploded group has more than N bits`.

---

## Important behaviors to know

### `--json` placement

`--json` can appear before or after the subcommand:

```bash
python3 vcd_analyzer.py --json info sim.vcd
python3 vcd_analyzer.py info sim.vcd --json
```

### Output truncation

Default `--limit` is 200 results. If `truncated: true` appears in JSON output, there are more results. Use `--limit 0` for unlimited, or increase the limit. The `total_is_exact` field tells you whether `total` is the true count or a lower bound (streaming commands stop counting after the first unshown result).

### Time fields in JSON

Every time value appears in three forms:
- `*_ticks`: integer, raw VCD timestamp (use for computation)
- `*_h`: human-readable string with unit (use for display to user)
- Some legacy fields without suffix equal `*_ticks`

### Value formatting

- 1-bit: `0`, `1`, `x`, `z`
- Multi-bit clean: `decimal (0xhex)` — e.g., `255 (0xff)`
- Multi-bit with unknowns: `b01xz` prefix notation
- Real/realtime: float string as-is from simulator
- Event type: `triggered`

### Filter vs condition signal matching

`--filter` allows multiple matches (substring/glob, returns all hits).
`--condition` signal patterns must resolve to **exactly one** signal. If ambiguous, the error message lists matching candidates — use a more specific path.

### Bit-exploded bus reassembly

QuestaSim writes a 32-bit bus as 32 separate 1-bit `$var` declarations with `[N]` suffixes. The tool auto-reassembles these into a single `bus[31:0]` signal. The `info` command reports `synthesized_buses` count. This is transparent — reassembled buses appear as normal multi-bit signals in all commands.

---

## Error handling

Errors go to stderr and exit with code 1. The error message is a single human-readable line starting with `Error:`. Common errors:

| Error | Cause | Fix |
|---|---|---|
| `condition signal pattern 'X' matches no signals` | Signal name not found | Use `list` to find correct path |
| `condition signal pattern 'X' matches N signals` | Ambiguous pattern | Use full path from `list` output |
| `end time must be >= begin time` | Reversed time range | Swap begin/end |
| `cannot open VCD file` | File not found | Check path |
| `VCD data section contains no value changes` | Empty or header-only VCD | File may be incomplete |

---

## What this tool does NOT do

- Does not read FSDB, SHM, WLF, or any non-VCD format (convert to VCD first using vendor tools)
- Does not modify or write VCD files
- Does not support OR in conditions (use multiple searches)
- Does not support arithmetic expressions in conditions (no `addr > 0xff`)
- Does not support bit-select in show/condition (no `data[7:4]=0xF` — filter by the full signal)
- Does not provide waveform visualization (text/JSON only)
- Default limit is 200 — always check `truncated` field and increase `--limit` if needed
