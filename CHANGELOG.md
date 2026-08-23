# Changelog

All notable changes to vcd_analyzer. Detailed per-release
notes live on the [GitHub Releases](https://github.com/neveltyc/VCD_ANALYZER/releases) page.

## [1.3.20](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.20) - 2026-08-23

Three correctness fixes found by review, plus documentation and validation cleanup. Every fix is locked with a regression test in the existing harnesses (`test_parser_direct_coverage.py`, `test_commands_direct_coverage.py`, `test_summary_begin_boundary.py`, `test_parser_optimizations.py`); the full suite passes.

- **`iter_events` coalesced multiple same-timestamp value changes per signal.** The per-timestamp `pending` dict kept only the last value per signal, so a legal `#10 0! 1! 0!` (IEEE 1364 permits any number of value_changes per simulation_time; delta-cycle style writers emit them) collapsed to a single event. `dump` no longer showed *every* value change, `summary` under-counted transitions and rise/fall edges, `search --changed` missed intra-timestamp edges (a `0->1->0` run looked like no change), and event variables did not count each trigger. Events are now kept in an ordered per-timestamp list: consecutive identical runs still coalesce, and the previously observed value is tracked across timestamp boundaries so a `$dumpall`/`$dumpon` checkpoint re-emitting the current value remains a no-op (1.3.19's static/active accounting is preserved). Snapshot/compare last-write-wins semantics are unchanged. The existing `test_parser_optimizations.py` per-timestamp counts are updated to the spec-correct "every value change" expectation.
- **`info` `t_max` collapsed to `t_min` when the final timestamp was followed by more than 4 MiB of value changes.** The backward tail scan read 64 KiB..4 MiB windows and gave up without a hit, with a comment claiming a >4 MiB timestamp-less tail is malformed — it is not: the IEEE 1364 `simulation_command` grammar places no bound on the value_change run after a `simulation_time`. A legal file `#0 ... #100 <8 MiB of changes>` reported `0s ~ 0s` and made `search` (implicit end) error with "begin time ... is after the last event at 0s". The tail scan is now a reverse token walk in 4 MiB windows: the first top-level `#<digits>` met from EOF is the last timestamp, so it stops at the first hit. Region skipping is the reverse dual of the forward skip-to-`$end` walk — a `$end` met in reverse enters a region whose body is skipped until the region's opening keyword — and that keyword includes `$dumpall`/`$dumpon`/`$dumpvars` (they are `$kw..$end` sections too, so the skip must exit on them or it leaks backward over the real last timestamp). Three refinements make the walk correct on ordinary large files: the region-skip state is carried across window boundaries and initialized at top level from EOF (so a region-free tail larger than one window is scanned correctly instead of being skipped wholesale), and the non-whitespace fragment at each window's low edge is stitched onto the next window before classification (so a fixed-size read cutting a `#123456` token can never let a truncated `#123` pass as a smaller valid timestamp). A `#<digits>` inside a `$comment`/`$vcdclose` body is never read as top level (matching the forward parser and `iter_events`), and `#<digits>` identifier_codes are excluded exactly as the parser does. Regression fixtures lock a >4 MiB region-free tail, a deep last timestamp before a large run, trailing `$dumpall`/`$dumpon`/`$comment`/`$vcdclose` sections, and a timestamp split across the window boundary.
- **`search --changed` collapsed multiple qualifying changes at one timestamp to a single event.** Even over the ordered event stream above, the event phase emitted at most one result per timestamp, so an event variable triggering several times at one time reported once (inconsistent with `dump`'s `[10, 10, 20]`), and a level signal satisfying the condition on more than one transition in a timestamp reported once. It now emits one event per qualifying change — an event var counts each trigger, a level signal exposes each matching transition — consistent with `dump` and the documented "count each trigger" contract. New `test_commands_direct_coverage.py` cases lock both the event-var and level-signal paths.
- **`search --changed` condition phase documented.** The condition is evaluated on the post-change state (the value after the transition at that timestamp): `"a=1"` reports edges into 1, `"a!=0"` reports a 0->1 edge. Now stated in the `--changed` help, the module docstring, README (en/zh) semantics notes, and `skill/SKILL.md`.
- **`info` now validates `--limit`.** `cmd_info` never called `_limit()`, so `--limit -5` was silently ignored in both the global and subcommand positions; it now raises the same `_LimitParseError` as every other command.
- **`info` text output on an empty data section** printed `Time : None ~ None (None)`; it now prints `Time : (no data in file)` (JSON was already structured).
- **Time-window boundary contract documented.** With no `--end`, the effective end is the file's last timestamp (a `--begin` past it is an error); with an explicit `--end` beyond the last timestamp, the last known state is extended into the window — the same last-known-value persistence as `snapshot`/`compare`. Recorded in the module docstring and README (en/zh).
- **Docs: `int_max_str_digits` is not PEP 678.** Five comments (four in `vcd_analyzer.py`, one in this file) attributed Python 3.11's decimal `int(str)` digit limit to PEP 678; PEP 678 is the unrelated exception `add_note()` proposal. The limit is the 3.11 GH-95770 hardening and needs no PEP citation.

## [1.3.19](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.19) - 2026-07-19

Correctness pass on free-format VCD (IEEE 1364-2005 permits several declarations or timestamps per physical line, and value_change identifiers that clash with structural tokens). Every fix below was reproduced with a minimal fixture and locked with a regression test in `verify/test_freeformat.py`; the previously-green suite still passes.

- **Header fast path dropped declarations packed onto one line.** `_parse_header`'s one-line fast path recognized a declaration by `startswith('$var ')` + `endswith(' $end')` alone, so `$var .. $end $var .. $end` (or two `$scope`) on a single line was handed to `_parse_var_tokens` as one record — the second signal, and nested scope, silently vanished (its later value changes then evaporated too). The fast path now runs only when the line carries exactly one `$end` as its final token; multi-declaration lines fall through to the token parser, which already handled them. This makes the "both header paths produce an identical signal table" property actually hold, and a new differential test asserts it on multi-declaration and indented lines.
- **`search` window silently truncated without `--end`.** `scan_time_range`'s backward `t_max` scan matched only line-anchored `#<digits>`, so a legal one-line-multiple-timestamps file (`1! #20 0! #30 ...`) reported `t_max` as the first timestamp and `search` (implicit end = `t_max`) returned false-negative results. The tail scan is now a section-aware token walk that considers every `#<digits>` token — mid-line included — while excluding those inside `$comment`/`$vcdclose` bodies or that are declared identifier_codes, exactly as the parser does.
- **`search` missed conditions that hold across a silent window.** In interval/segment mode the initial condition check only ran on the first event after `--begin`; a selected signal with no events inside `(begin, end]` left it unevaluated, yielding a false "No interval" even when `snapshot` confirmed the condition. The initial state is now evaluated from the baseline after the event loop when no in-window event triggered it.
- **Rejected `b`/`r` value_change leaked its identifier.** When `_consume_value_change` rejected a malformed real/binary value (e.g. `rnan`, `b1012` — NaN is legal `%g` output) it returned before consuming the following identifier, which then re-parsed at top level: `rnan x!` fabricated a phantom scalar change on signal `!`. A `b`/`r` opener now consumes its identifier before validating the value, so a malformed value produces no event and no cascade.
- **`info` time range diverged from the event stream.** The `t_min` forward scan skipped a data-section `$comment .. $end` by reading *subsequent* lines for `$end`, over-running a single-line comment (whose `$end` was on the same line) and swallowing the real first timestamp. It is now a flat token walk with a skip flag, mirroring `iter_events`, so a same-line `$end` closes the section correctly.
- **Oversized timestamp crashed `info`.** The backward scan's bare `int()` on `#<digits>` bypassed the hardened `_parse_vcd_timestamp_token`, so a 5000-digit timestamp raised an unhandled `ValueError` (Python 3.11+ `int_max_str_digits` limit) instead of the clean CLI error `dump` already produced. All `#T` parsing in `scan_time_range` now routes through the hardened helper (bounded digit length, int64 cap), removing three bare `int()` sites.
- **`summary` counted checkpoint records as changes.** `$dumpall`/`$dumpon` re-emit every signal's current value; a never-changing signal was reported `ACTIVE chg=1`. The change counter now increments only on a genuine `val != prev` transition, so redundant same-value records keep the signal static (rise/fall were already correct).

Minor: `list` prints `Matched: n/total` in consistent alias-path units (no more `2/1`); `search --begin` past the last event without `--end` says so instead of "end time must be >= begin time"; `--limit` validation raises a dedicated `_LimitParseError` (wired into `main()`); dropped a redundant local `import os` and the uppercase-`P` value-change opener the parser never emits.

## [1.3.18](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.18) - 2026-07-18

Fix `info`'s `time_max` collapsing to `time_min` on VCD files whose lines are indented. `scan_time_range` scans `t_max` backward from EOF with a regex that anchored `#<digits>` timestamps to the start of a line (`(?:^|\n)#(\d+)`). VCD is a free-format token stream where leading whitespace before a token — including a timestamp — is legal, so any dump that indents its body (e.g. the checked-in GordonMcGregor sample, indented 4 spaces per line) matched nothing, and the silent `t_max = t_min` fallback masked the miss as a plausible-looking `500ns ~ 500ns` instead of the correct `500ns ~ 2.01us`. The `t_min` forward scan already tolerated this because it uses `line.split()`; the two scanners had drifted apart. The regex now allows leading horizontal whitespace (`(?:\A|\n)[ \t]*#(\d+)`), which still ignores a mid-line `#5` value-change identifier because `[ \t]*` only skips to the line's first token. Additionally, when the backward scan reads the entire data section without a hit it now degrades to a full forward scan for the last `#T` token rather than silently returning `t_max = t_min`. Regression coverage added: `test_scan_time_range_tolerates_indented_timestamps` and a `time_max_ticks == 2010` assertion on the GordonMcGregor sample in `test_external_samples.py`.

## [1.3.17](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.17) - 2026-05-29

Add a common-shape fast path to the `$var` declaration parser, adopted from the same downstream optimization pass that contributed 1.3.15. `_parse_var_tokens` previously ran two `_collect_bracket_tokens` scans for every variable; on files that declare hundreds of thousands of signals (VCS/Verdi headers, large UVM testbenches) that is a measurable per-command startup cost. The two dominant token layouts emitted by VCS, Verilator, and Icarus — `vtype width sym name` and `vtype width sym name [range]`, with an integer width — are now handled directly, skipping both bracket scans. Bracketed or split-range sizes and any other shape fall through to the existing general parser, so output is byte-for-byte identical (verified against the prior revision across all fixtures, the one-line header fast path, and a 512 MB FST-to-VCD trace carrying 275 K `$var` records, including wide-bus bit-selects and nested scopes). The one-line header fast path from 1.3.15 feeds this same helper, so both header paths benefit. Modest on its own and only touches the header phase; the dominant full-scan cost remains the per-line tokenization inherent to the text format.

## [1.3.16](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.16) - 2026-05-29

Inline the over-wide value clamp on the value-change hot path. `iter_events` previously called `_clamp_overwide_logic_value()` for every standalone value change; on large dumps ~93% of those values are single-character scalars that can never exceed their declared width, so the call was almost pure function/dict/len overhead across tens of millions of events. The guard is now inlined — scalars and in-width values are stored directly, and the helper is invoked only for the rare genuinely over-wide value, where it remains the single source of truth. Output is byte-for-byte identical (verified against the prior revision across all fixtures, external samples, and a 512 MB VCS trace, including the malformed over-wide case). Modest on its own; the dominant full-scan cost remains the per-line tokenization inherent to the text format.

## [1.3.15](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.15) - 2026-05-29

Two parser optimizations adopted from a contributed optimization pass, with output verified byte-for-byte identical to 1.3.14. First, the data-section tokenizer reads in large chunks and splits in C with a carry buffer for tokens that span chunk boundaries, instead of iterating line by line; FST-to-VCD converters emit tens of millions of one-token lines, and this removes the per-line Python overhead on them. Second, the header parser gains a fast path for the common one-declaration-per-line form (`$var wire 1 ! clk $end`), falling back to the tolerant token parser for free-form or multi-line declarations; both paths share a single `_parse_var_tokens` helper so the parsed signal table is identical. Roughly 1.1-1.25x on summary/dump/snapshot/compare over a 43 MB Icarus trace and an FST2VCD-style trace, with larger gains on filtered queries. A contributed regex-based selected-signal scanner was evaluated and rejected: it dropped value-change events on dense traces (an off-by-one in non-overlapping regex matching) and was slower than the general iterator on filtered queries, so it was not adopted. New regression tests cover chunk-boundary tokenization and header fast-path equivalence.

## [1.3.14](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.14) - 2026-05-29

Stream `dump` text output instead of materializing every event into a dict and printing line by line: lines are formatted on the fly and flushed in batches, cutting a full `dump --limit 0` over a 40 MB trace to roughly a third of its former wall-clock time with byte-identical output. JSON output is unchanged. Add `verify/bench.py`, a self-contained benchmark and equivalence harness that generates a deterministic synthetic VCD, times each command with output sent to `/dev/null` (so a command is measured rather than the harness's pipe-draining cost), and with `--baseline` compares two copies while verifying their stdout is byte-for-byte identical.

## [1.3.13](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.13) - 2026-05-29

Speed up the value-change hot path for large VCDs (roughly 2x on summary, snapshot, and compare over a 43 MB trace) with no change in output. Replace per-character `all()`/`any()` 4-state validation with C-level `str.translate`, flatten the data-section tokenizer to walk per-line token lists by index instead of resuming a per-token generator, inline the common 1-bit scalar value-change, and defer the over-wide 4-state scan in `fmt_val`/`_clamp_overwide_logic_value` behind a cheap width guard. `cmd_dump` now memoizes the formatted timestamp across events that share it.

## [1.3.12](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.12) - 2026-05-28

Replace double-scan paths with single-pass iter_events in summary, compare, and search. Refine summary_rows baseline phase to avoid redundant stats-dict creation, using a lightweight baseline dict with lazy stats dispatch.

## [1.3.11](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.11) - 2026-05-28

Dramatically speed up filtered iteration and time-range scanning for large VCDs

## [1.3.10](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.10) - 2026-05-27

Fix `summary` begin-boundary transition counting

## [1.3.9](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.9) - 2026-05-25

Eliminate duplicated value-change parsing in data scanning paths

## [1.3.8](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.8) - 2026-05-25

Harden input validation and error reporting

## [1.3.7](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.7) - 2026-05-25

Fix literal bus-range globs and escaped-scope reporting

## [1.3.6](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.6) - 2026-05-25

Clamp malformed over-wide logic values

## [1.3.5](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.5) - 2026-05-25

Remove obsolete search helper

## [1.3.4](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.4) - 2026-05-25

Support width-aware 4-state matching

## [1.3.3](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.3) - 2026-05-25

Refine changed-mode and truncation behavior

## [1.3.2](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.2) - 2026-05-25

Preserve begin-boundary edges in changed mode

## [1.3.1](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.1) - 2026-05-24

Add truncation accounting for streaming commands

## [1.3.0](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.0) - 2026-05-24

Redesign search around conditions and observations

## [1.2.12](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.12) - 2026-05-24

Capture richer header metadata

## [1.2.11](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.11) - 2026-05-24

Improve malformed token recovery

## [1.2.10](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.10) - 2026-05-24

Continue parser hardening

## [1.2.9](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.9) - 2026-05-24

Cap integer parsing in headers

## [1.2.8](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.8) - 2026-05-24

Validate timestamp tokens defensively

## [1.2.7](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.7) - 2026-05-24

Refine safety bounds and filtering

## [1.2.6](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.6) - 2026-05-24

Tighten regex and malformed-input handling

## [1.2.5](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.5) - 2026-05-24

Add environment-controlled parser limits

## [1.2.4](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.4) - 2026-05-24

Harden time parsing and CLI guards

## [1.2.3](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.3) - 2026-05-24

Refine summary and search payloads

## [1.2.2](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.2) - 2026-05-25

Expand time metadata fields

## [1.2.1](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.1) - 2026-05-24

Polish CLI output plumbing

## [1.2.0](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.2.0) - 2026-05-24

Remove edges command and add shared output helpers

## [1.1.8](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.1.8) - 2026-05-24

Switch legacy search to interval reporting

## [1.1.7](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.1.7) - 2026-05-24

Improve malformed-input recovery

## [1.1.6](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.1.6) - 2026-05-24

Protect parsing from structural-token confusion

## [1.1.5](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.1.5) - 2026-05-24

Simplify token scanning paths

## [1.1.4](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.1.4) - 2026-05-24

Polish search and output consistency

## [1.1.3](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.1.3) - 2026-05-24

Improve reassembly and reporting stability

## [1.1.2](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.1.2) - 2026-05-24

Refine parser behavior

## [1.1.1](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.1.1) - 2026-05-24

Harden multiline token cleanup

## [1.1.0](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.1.0) - 2026-05-24

Rewrite parser around token-based handling, remove handshake command

## [1.0.0](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.0.0) - 2026-05-24

Initial public release — core CLI, parser, and 6 subcommands

