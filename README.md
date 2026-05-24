        # VCD Analyzer

        Version `1.1.2`

        Author: `neveltyc <neveltyc@gmail.com>`

        ## Overview

        `vcd_analyzer.py` is a command-line helper for inspecting Verilog VCD waveforms during RTL debug.

        ## Highlights

        - Polish header and event parsing without changing the CLI contract.
- Improve robustness around mixed declaration formatting and data replay.
- Carry the existing smoke fixtures forward unchanged.

        ## Commands

        - `info`
- `list`
- `dump`
- `summary`
- `edges`
- `snapshot`
- `compare`
- `search`

        ## Usage

        ```text
        VCD waveform analyzer for Agent-based RTL debug.

Usage: vcd_analyzer [--json] <command> <file> [options]

Commands:
  info       <file>                               File overview (timescale, signal count, time span, scopes)
  list       <file> [--filter K1,K2]               List signals with path and bit width
  dump       <file> [--begin T] [--end T] [--filter K1,K2]   Print signal value changes in time order
  summary    <file> [--begin T] [--end T] [--filter K1,K2]   Per-signal stats: change count, unique values, static detection
  edges      <file> [--begin T] [--end T] [--filter K1,K2]   1-bit edge detection with frequency estimation
  snapshot   <file> --at T [--filter K1,K2]        All signal values at a given time point
  compare    <file> --at T1,T2 [--filter K1,K2]    Diff signal values between two time points
  search     <file> --value V [--signal K] [--begin T] [--end T] [--filter K1,K2]   Find when signal equals a value

Global option:
  --json    Output structured JSON instead of text (for programmatic parsing)

Argument formats:
  <file>          VCD file path
  --filter K1,K2  Comma-separated keywords, substring-matched against signal paths (case-insensitive)
                  e.g. --filter clk,rst   --filter tdata,tvalid   --filter u_dll_ctrl
  --begin T       Start time with optional unit suffix: 0, 100ns, 17.5us, 1ms, 500ps, 200fs
  --end T         End time, same format as --begin. Omit for no upper bound
  --at T          Time point for snapshot. For compare: two points comma-separated: --at 17.5us,17.7us
  --value V       Target value for search: decimal (42), hex (0x2a),
                  or binary with explicit prefix (0b101010 or b101010).
                  Leading-zero forms like "0010" parse as decimal 10;
                  use "0b0010" to mean binary 2.
  --signal K      Additional keyword filter for search, targets signal name specifically

Examples:
  vcd_analyzer info sim.vcd
  vcd_analyzer list sim.vcd --filter tdata,tvalid,tready
  vcd_analyzer dump sim.vcd --begin 17.5us --end 17.6us --filter clk,rst,state
  vcd_analyzer summary sim.vcd --filter dll_st,locked
  vcd_analyzer edges sim.vcd --filter clk_500M
  vcd_analyzer snapshot sim.vcd --at 17.55us --filter init_done,state
  vcd_analyzer compare sim.vcd --at 17.535us,17.56us --filter init_done,link_active,state
  vcd_analyzer search sim.vcd --signal state --value 5
  vcd_analyzer search sim.vcd --value 0xff --begin 100ns --end 500ns
  vcd_analyzer --json summary sim.vcd --filter tvalid,tready
        ```

        ## Tests

        The repository ships with a sanitized unittest-based regression library under `tests/`.
        The VCD fixtures use generic module and signal names and do not preserve any private customer paths.

        Run the tests with:

        ```bash
        python -m unittest discover -s tests -p "test_*.py"
        ```
