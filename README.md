# VCD Analyzer

Command-line helper for inspecting Verilog VCD waveforms during RTL debug.
Built for agent-assisted and interactive use.

## Quick start

```bash
python vcd_analyzer.py info sim.vcd
python vcd_analyzer.py list sim.vcd --filter clk,rst
python vcd_analyzer.py dump sim.vcd --begin 100ns --end 200ns --filter state
python vcd_analyzer.py search sim.vcd --condition "valid=1,ready=1" --show data
```

Full usage details and all argument formats are in `python vcd_analyzer.py --help`
or in the docstring at the top of [vcd_analyzer.py](vcd_analyzer.py).

## Commands

| Command    | Purpose |
|------------|---------|
| `info`     | File overview: timescale, signal count, time span, scopes |
| `list`     | List signals with path and bit width |
| `dump`     | Print value-change events in time order |
| `summary`  | Per-signal window stats: active/static, change count, rise/fall edges |
| `snapshot` | Known signal values at a given time point |
| `compare`  | Diff signal values between two time points |
| `search`   | Condition-based search with optional --show and --changed observation |

## JSON output

All commands support `--json` for compact structured output. Time fields include
both human-readable (`_h`) and raw tick (`_ticks`) forms.

```bash
python vcd_analyzer.py --json info sim.vcd
python vcd_analyzer.py --json search sim.vcd --condition "state=5" --show data
```

## Project structure

```
vcd_analyzer.py       Main script (single-file, stdlib only)
tests/                unittest-based regression suite
tests/fixtures/       Sanitized VCD fixtures (generic names)
version_notes/        Per-version change logs
archive/              Historical version snapshots
```

## Tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Version history

Detailed change logs in [version_notes/](version_notes/).

- `1.3.9` — Eliminate duplicated value-change parsing
- `1.3.8` — Harden input validation and error reporting
- `1.3.7` — Fix literal bus-range globs and escaped-scope reporting
- `1.3.0` — Redesign search around conditions and observations
- `1.0.0` — Initial public release

## Author

`neveltyc <neveltyc@gmail.com>`

## License

[MIT](LICENSE)
