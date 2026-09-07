# Changelog

All notable changes to vcd_analyzer. Detailed per-release
notes live on the [GitHub Releases](https://github.com/neveltyc/VCD_ANALYZER/releases) page.

## [1.5.1](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.5.1) - 2026-09-08

### Fixed

- **Non-finite real values are no longer silently dropped.** C99 `%g` renders
  non-finite doubles as `inf`/`-inf`/`nan`, and IEEE 1364's real_number is
  `%g` output — but the parser's real regex rejected them, so the whole
  value_change record vanished from `dump`, `info`'s time range, and
  `summary` counts with no diagnostic. They are now kept in the stream
  verbatim (locked by `verify/test_real_nonfinite.py`). Equality targets
  still reject `inf`/`nan`: nan never compares equal and inf has no finite
  target, so no condition can match one — a stated limitation, not data loss.
- **`summary`'s distinct-value (`unique`) set grew without bound** — a 32-bit
  counter over tens of millions of changes kept every value string alive.
  The set now caps at `VCD_ANALYZER_MAX_UNIQUE_VALUES` (default 65536, read
  per call like `VCD_ANALYZER_TOKEN_CHUNK_SIZE`); beyond the cap the count is
  a lower bound and the row says so: JSON `unique_is_exact: false` (key
  appears only when capped), text `uniq=N+`. No existing key changed name,
  type, or meaning.

### Internal

- Removed dead code: `fmt_time`'s unreachable trailing return, `_limit`'s
  unused `cmd` parameter, and `cmd_dump`'s duplicate `last_t`/`cur` sentinels
  (one memoized sentinel now drives both the `T=` header and the formatted
  time).
- CLI: Ctrl-C exits 130 instead of printing a traceback; stdout/stderr are
  forced to UTF-8 (`errors='replace'`) so a legacy Windows codepage cannot
  turn a valid dump into `UnicodeEncodeError`.

## [1.5.0](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.5.0) - 2026-08-24

`search`'s condition system, rebuilt around the shape the downstream [RWaveAnalyzer](https://github.com/neveltyc/RWaveAnalyzer) port converged on: the edge trigger moves out of a flag and into the condition grammar, and OR becomes a repeatable flag. Along the way three silent-wrong-answer bugs found while comparing the two implementations are fixed — a real signal's value read as a bit string, a mis-typed in-string boolean accepted as an opaque literal, and a repeated `--condition` quietly discarding all but the last. Every non-`search` command is byte-identical to 1.4.0 at equal `--limit` (verified with `verify/bench.py --baseline`); the full suite passes, now 162 tests including three new files.

### Changed

- **BREAKING: the edge trigger is now a condition term, `changed(SIG)`; the `--changed` flag is removed.** `--condition "changed(req),ready=0"` fires at the ticks where `req` transitions while `ready=0` holds. As a flag it applied to the whole query, so an edge could not be scoped to one OR clause and two signals could not be required to transition together; both now fall out of the grammar. `changed(a),changed(b)` requires both to transition on the same tick. A `changed()` term switches `search` to event mode, and then *every* clause must carry one — mixing tick-shaped and span-shaped clauses is a usage error rather than a silent pick of one. With no `--show`, event mode shows the `changed()` signals; the JSON `changed` echo is now an **array** of paths. `--changed` now fails with a pointer to the new syntax. `changed()`, `changed(req)=1`, and `changed(a,b)` each get their own error text.
- **BREAKING: `--condition` is repeatable and ORs its clauses (OR-of-ANDs).** Each `--condition` is one comma-separated AND clause; the search holds wherever *any* clause holds. The canonical use is multi-channel protocols — one clause per channel to find when any channel handshakes — with no in-string boolean syntax. Interval, segment, and event modes are unchanged; OR only widens *when* the condition holds, and cost scales with the distinct signals referenced, not the clause count. Clauses that are identical, term-order permuted, or alias-equivalent fold silently (first occurrence kept); the same value in different bases (`5` vs `0x5`) does not fold. A single clause echoes exactly as before; several render as `(…) OR (…)` in both `condition` and `condition_resolved`. This is breaking only in that repeating the flag used to be silently ignored: argparse kept the **last** `--condition` and dropped the rest, so `--condition "req=1" --condition "ack=1"` confidently answered a question it was never asked.
- **BREAKING: event mode evaluates level terms on the tick's settled state.** IEEE 1364 fixes neither the order nor the count of `value_change`s within one `simulation_time`, but the old per-record evaluation read the condition after each record in turn — so on a trace where `req` rises and `ready` falls at the same timestamp, merely swapping those two lines changed `--changed req --condition "ready=1"` from three events to two. Every signal except the one transitioning is now read at the settled state. The transitioning signal itself still reads the value it took **at that edge**, because the order of one signal's own records is the delta-cycle sequence and does carry meaning — which is what keeps `changed(s),s=1` meaning "rising edge of s" even when `s` toggles inside a tick. Emission stays per-record (1.3.20's contract: an event variable counts each trigger, an intra-tick `0->1->0` run exposes each transition); a clause requiring several signals to transition together reports the tick once, since coincidence is a tick property.
- **The default `--limit` is 500, up from 200,** and a clipped result says so plainly: the text notice stands off by a blank line, leads with `TRUNCATED`, and names both `--limit N` and `--limit 0`. Under `--json` it gains a `hint` field, since `truncated: true` among a dozen keys is easy to skim past; it appears only when something was clipped, so no existing key changed name, type, or meaning.

### Fixed

- **Condition matching read a real signal's value as a bit string.** A real/realtime signal carries the simulator's `%g` text as its value, so a real `100.0` is dumped as `r100` — which `val_to_int` parsed as binary `100` = 4. On the same signal that made `dac=4` match spuriously *and* `dac=100` miss: a false positive and a false negative at once. Values are now classified by the signal's declared kind, reusing the `_sid_kind` table 1.4.0 already precomputes. Real signals compare numerically (`dac=100`, `dac=3.14`, `dac=1e-9`); logic signals keep exactly today's numeric/4-state/width-aware path. An event variable has no level at all, so a level term on one is refused at resolve time with a pointer to `changed(SIG)` rather than quietly matching nothing; likewise a bit pattern against a real signal, or a real number against a logic signal.
- **An unusable condition target was kept as an opaque literal instead of being rejected.** `_parse_target_value` ended in an unconditional fallback that accepted any string as a literal target, and a literal target can only ever compare unequal. Since the tool has no in-string boolean syntax, `--condition "a=1 OR b=1"` parsed as the single term `a` = the text `1 or b=1`, and the command reported a confident `No interval ... where tb.a=1 OR b=1.` The bare-target grammar is now closed: all-digits is a decimal, all `0/1/x/z` is a 4-state literal, a number with a fraction or exponent is a real target, and anything else — `1 OR b=1`, `1|b=1`, `IDLE`, `nan`, `inf` — is an error naming the accepted forms and the fact that OR is spelled by repeating the flag.

### Internal

- New `_transition_groups`, the per-timestamp grouping of 1.4.0's `iter_transitions` view (as `_event_groups` is of `iter_events`). Carrying `prev` and `kind` per record is what lets event mode compute a tick's transition set — and so answer "did `a` and `b` change together?" — without re-deriving either. `_term_key` is shared by the within-clause term de-dup and the cross-clause clause de-dup so the two cannot drift apart.
- New `verify/test_search_or.py`, `verify/test_search_changed_term.py`, and `verify/test_condition_kinds.py` (55 cases), ported from the downstream `search_or_conditions.rs` / `search_changed_condition.rs` suites plus this tool's own finer per-record contract, the intra-timestamp record-order-independence lock, and the real/event kind cases.

## [1.4.0](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.4.0) - 2026-08-24

Internal refactor separating the event stream from derived state into one change-semantics core with three distinct views. No change to any command's output — proven byte-identical to 1.3.20 by `verify/bench.py --baseline` across every command and by a 674-case per-command differential over the checked-in fixtures and external samples; the full suite (now including `verify/test_layering.py`) passes.

Before this, `VCDParser.iter_events` was the only data-plane API, and it simultaneously produced events, coalesced no-op re-assertions, tracked event-variable semantics, and assembled bit-buses. Every command re-derived what it needed on top of that single stream: `cmd_search` regrouped events by timestamp by hand and re-checked `signals[...]['type'] == 'event'` (duplicating the check inside `iter_events`), `_summary_rows` tracked its own `prev`, and snapshot/compare folded the stream in ad-hoc helpers. Signal "kind" (event/real/vector/scalar) had no first-class representation. The 1.3.20 correctness fixes were real, but they were patched into that single fused stream one consumer at a time — the layering itself was the root issue.

- **One core, three views.** The value-change loop is now `VCDParser._iter_changes`, yielding `(time, sid, prev, value)`; it owns no-op coalescing, cross-timestamp `last_val` persistence, event-trigger counting, bit-bus assembly, the `t0` catch-up and `sids` laziness. `iter_events` is a thin projection to `(time, sid, value)` (output unchanged); `iter_transitions` adds `prev` and `kind`; `state_at`/`state_before`/`state_pair` fold the stream to settled `{sid: value}` (replacing the `_build_snapshot*` helpers).
- **Signal kind is precomputed once.** `_event_sids` (a frozenset) and `_sid_kind` are built at the end of header parsing. The no-op bypass on the hot path is now a set-membership test instead of a per-event `signals.get(sid)['type']` lookup, and this is the one place `type == 'event'` is evaluated anywhere. Removing the per-event lookup also makes the value-change hot path slightly faster (~1.02–1.08× on dump/summary/snapshot/compare over the benchmark traces).
- **Consumers use the right view.** snapshot/compare → `state_at`/`state_pair`; summary → `iter_transitions` (using the stream's `prev`, dropping its own `prev` field; the width-based scalar test is kept so 1-bit event/real signals still report rise/fall `0`, not `null`); `search --changed` → `iter_transitions` with per-event evaluation, so the hand-rolled per-timestamp regrouping and the duplicate `type == 'event'` check are gone; interval/segment `search` → the previously-dead `_event_groups` helper, the legitimate settled-state-per-timestamp view. `cmd_dump` remains the raw-event consumer via `iter_events`.
- **Cleanup.** Removed dead code (`_build_snapshot`/`_build_snapshot_before`/`_build_snapshot_pair`, `_data_tokens`), revived `_event_groups`, and corrected a stale `_bit_map` shape comment. New `verify/test_layering.py` locks the three views, the precomputed kind, and their equivalence (`iter_events` == `iter_transitions` minus prev/kind; `state_at` == fold of `iter_events`).

## [1.3.20](https://github.com/neveltyc/VCD_ANALYZER/releases/tag/v1.3.20) - 2026-08-24

Three correctness fixes found by review, plus documentation and validation cleanup. Every fix is locked with a regression test in the existing harnesses (`test_parser_direct_coverage.py`, `test_commands_direct_coverage.py`, `test_summary_begin_boundary.py`, `test_parser_optimizations.py`); the full suite passes.

- **`iter_events` coalesced multiple same-timestamp value changes per signal.** The per-timestamp `pending` dict kept only the last value per signal, so a legal `#10 0! 1! 0!` (IEEE 1364 permits any number of value_changes per simulation_time; delta-cycle style writers emit them) collapsed to a single event. `dump` no longer showed *every* value change, `summary` under-counted transitions and rise/fall edges, `search --changed` missed intra-timestamp edges (a `0->1->0` run looked like no change), and event variables did not count each trigger. Events are now kept in an ordered per-timestamp list: consecutive identical runs still coalesce, and the previously observed value is tracked across timestamp boundaries so a `$dumpall`/`$dumpon` checkpoint re-emitting the current value remains a no-op (1.3.19's static/active accounting is preserved). Snapshot/compare last-write-wins semantics are unchanged. The existing `test_parser_optimizations.py` per-timestamp counts are updated to the spec-correct "every value change" expectation.
- **`info` time range rebuilt on a single forward scanner (`scan_time_range` was a recurring correctness hazard).** The old `t_max` reconstructed VCD grammar *backwards* from an arbitrary byte offset with no synchronization point, and kept breaking: on a legal `#0 ... #100 <8 MiB of changes>` it reported `0s ~ 0s` (making `search`'s implicit end error out), it swallowed the last timestamp before a trailing `$dumpall`/`$dumpon` block, and a fixed-size read could split a `#123456` token into a bogus `#123`. Both ends are now computed by one forward scanner, `_scan_timestamps`, that replays `iter_events`'s own top-level grammar (reusing `_consume_value_change` and `_is_structural_token` verbatim), so the reported range is derived by *exactly* the rules the event stream parses with — `$comment`/`$vcdclose` bodies are drained to `$end`, `$dumpall`/`$dumpon`/`$dumpvars` are markers, a top-level `#<digits>` is always a timestamp, and a `#<digits>` that is a declared identifier_code operand is consumed, not miscounted. `t_min` reads small lazy chunks from the data start and stops at the first `#T`; `t_max` reads a small tail window from EOF (default 64 KiB, `VCD_ANALYZER_TAIL_WINDOW`) and grows it geometrically until a top-level `#T` is found, so an unbounded trailing value_change run or a large `$dumpall` checkpoint no longer collapses the range. A window that begins inside a section body is handled by a resync (a bare `$end` before any opener means the window started mid-section — discard and resume), and the final grow reaches the data-section floor: a provably-correct full forward scan the reverse walk never had. This is also *faster* — `info` runs ~1.5× the speed of the previous reverse scan on 8–54 MB traces (byte-identical output) because the small window avoids splitting a 4 MiB tail and `t_min` no longer reads a large chunk. Regression fixtures lock grow-on-miss, a window starting inside a trailing `$comment`/`$vcdclose`, a boundary-split timestamp, b/r/p operand disambiguation, window-size invariance (tiny vs. one full pass), and a real >4 MiB region-free tail.
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

