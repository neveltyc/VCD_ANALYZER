"""Regression tests for the 1.3.19 free-format / consistency fixes (B1-B7 and
the associated minor issues). Each test encodes one previously-confirmed bug so
it cannot silently return.
"""
import json

import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd, run_cli


def _alias_paths(path):
    """All signal alias paths registered by the parser, sorted."""
    v = va.VCDParser(str(path))
    out = []
    for info in v.signals.values():
        out.extend(info['aliases'])
    return sorted(out)


def _events(path, **kw):
    v = va.VCDParser(str(path))
    return v, [(t, sid, val) for t, sid, val in v.iter_events(**kw)]


def _sid_for(v, path):
    return next(sid for sid, info in v.signals.items() if info['path'] == path)


# --------------------------------------------------------------------- B1
def test_b1_multiple_declarations_on_one_physical_line(tmp_path):
    # Two $scope and two $var declarations packed onto single lines (legal
    # free-format VCD). The fast path must not keep only the first of each.
    text = (
        '$timescale 1ns $end\n'
        '$scope module tb $end $scope module core $end\n'
        '$var wire 1 ! clk $end $var wire 1 " rst $end\n'
        '$upscope $end\n$upscope $end\n'
        '$enddefinitions $end\n#0\n0!\n0"\n#10\n1!\n1"\n'
    )
    p = write_vcd(tmp_path, text)
    assert _alias_paths(p) == ['tb.core.clk', 'tb.core.rst']
    # The dropped signal's value changes must also survive.
    v, ev = _events(p)
    rst = _sid_for(v, 'tb.core.rst')
    assert [(t, val) for t, sid, val in ev if sid == rst] == [(0, '0'), (10, '1')]


def test_b1_fast_path_matches_token_parser_on_multidecl(tmp_path):
    # Differential guard for the CHANGELOG's long-standing "both header paths
    # produce an identical signal table" claim, now on a multi-declaration line.
    # A tab after the keyword dodges the fast path onto the token parser.
    fast = (
        '$scope module m $end\n'
        '$var wire 1 ! a $end $var wire 2 " b [1:0] $end\n'
        '$enddefinitions $end\n#0\n'
    )
    slow = fast.replace('$var ', '$var\t').replace('$scope ', '$scope\t')
    a = _alias_paths(write_vcd(tmp_path, fast, 'fast.vcd'))
    b = _alias_paths(write_vcd(tmp_path, slow, 'slow.vcd'))
    assert a == b == ['m.a', 'm.b[1:0]']


# --------------------------------------------------------------------- B2
def test_b2_multiple_timestamps_per_line(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! v $end\n', '#10\n1! #20 0! #30 1! #40 0! #50 1!\n'))
    info = json.loads(run_cli(['--json', 'info', str(p)]).stdout)
    assert info['time_max_ticks'] == 50
    # search with no --end uses t_max as the implicit window end: must find all
    # three v=1 stretches, not just the first.
    obj = json.loads(run_cli(['--json', 'search', '--condition', 'v=1', str(p)]).stdout)
    assert sorted(iv['begin_ticks'] for iv in obj['intervals']) == [10, 30, 50]


# --------------------------------------------------------------------- B3
def test_b3_condition_holds_across_silent_window(tmp_path):
    # rst_n is 0 for the whole trace and never changes inside (20, 80]; the
    # interval must still be reported, not a false "No interval".
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! rst_n $end\n$var wire 1 " clk $end\n',
        '#0\n0!\n0"\n#10\n1"\n#20\n0"\n#100\n'))
    obj = json.loads(run_cli(
        ['--json', 'search', '--begin', '20', '--end', '80',
         '--condition', 'rst_n=0', str(p)]).stdout)
    ivs = obj['intervals']
    assert len(ivs) == 1
    assert ivs[0]['begin_ticks'] == 20 and ivs[0]['end_ticks'] == 80
    # Also the window-starts-at-0 variant.
    obj0 = json.loads(run_cli(
        ['--json', 'search', '--begin', '0', '--end', '50',
         '--condition', 'rst_n=0', str(p)]).stdout)
    assert len(obj0['intervals']) == 1 and obj0['intervals'][0]['end_ticks'] == 50


# --------------------------------------------------------------------- B4
def test_b4_rejected_real_token_does_not_cascade(tmp_path):
    # 'rnan x!' — NaN is legal %g output that _REAL_RE rejects. The identifier
    # 'x!' must be consumed with it, never re-read as a scalar 'x' on signal '!'.
    text = (
        '$timescale 1ns $end\n$scope module tb $end\n'
        '$var wire 1 ! flag $end\n$var real 64 x! rsig $end\n'
        '$upscope $end\n$enddefinitions $end\n#0\n0!\n#10\nrnan x!\n'
    )
    v, ev = _events(write_vcd(tmp_path, text))
    flag = _sid_for(v, 'tb.flag')
    assert [(t, val) for t, sid, val in ev if sid == flag] == [(0, '0')]  # no phantom @10


def test_b4_rejected_binary_token_does_not_cascade(tmp_path):
    # 'b1012 1&' — '2' is not a legal 4-state bit. '1&' must not become a scalar
    # '1' on signal '&'.
    text = (
        '$timescale 1ns $end\n$scope module tb $end\n'
        '$var wire 1 & gate $end\n$var wire 4 1& bus $end\n'
        '$upscope $end\n$enddefinitions $end\n#0\n0&\n#10\nb1012 1&\n'
    )
    v, ev = _events(write_vcd(tmp_path, text))
    gate = _sid_for(v, 'tb.gate')
    assert [(t, val) for t, sid, val in ev if sid == gate] == [(0, '0')]  # no phantom @10


# --------------------------------------------------------------------- B5
def test_b5_single_line_comment_in_data_section(tmp_path):
    # A single-line '$comment .. $end' in the data area must not swallow the
    # first timestamp during the t_min scan.
    text = (
        '$timescale 1ns $end\n$scope module tb $end\n$var wire 1 ! clk $end\n'
        '$upscope $end\n$enddefinitions $end\n'
        '$comment reset applied $end\n#0\n0!\n#5\n$dumpall 0! $end\n'
        '#10\n1!\n#20\n0!\n#30\n1!\n'
    )
    info = json.loads(run_cli(['--json', 'info', str(write_vcd(tmp_path, text))]).stdout)
    assert info['time_min_ticks'] == 0 and info['time_max_ticks'] == 30


# --------------------------------------------------------------------- B6
def test_b6_oversized_timestamp_is_a_clean_cli_error(tmp_path):
    text = (
        '$timescale 1ns $end\n$scope module tb $end\n$var wire 1 ! clk $end\n'
        '$upscope $end\n$enddefinitions $end\n#0\n0!\n#' + '9' * 5000 + '\n1!\n'
    )
    r = run_cli(['info', str(write_vcd(tmp_path, text))])
    assert r.returncode != 0
    assert 'too long' in r.stderr and 'Traceback' not in r.stderr


# --------------------------------------------------------------------- B7
def test_b7_dumpall_redump_of_unchanged_signal_stays_static(tmp_path):
    # A $dumpall re-emits a never-changing signal's current value; that must not
    # be counted as a transition (static, chg=0), only genuine changes count.
    text = (
        '$timescale 1ns $end\n$scope module tb $end\n$var wire 1 ! stable $end\n'
        '$upscope $end\n$enddefinitions $end\n#0\n0!\n#10\n$dumpall 0! $end\n#20\n'
    )
    obj = json.loads(run_cli(['--json', 'summary', str(write_vcd(tmp_path, text))]).stdout)
    assert obj['active'] == 0 and obj['static'] == 1
    row = obj['rows'][0]
    assert row['kind'] == 'static' and row['changes'] == 0


# ------------------------------------------------------------------- minors
def test_minor_list_matched_denominator_counts_aliases(tmp_path):
    # One signal referenced under two names: "Matched: 2/2", not "2/1".
    text = (
        '$timescale 1ns $end\n$scope module tb $end\n'
        '$var wire 1 ! a $end\n$var wire 1 ! b $end\n'
        '$upscope $end\n$enddefinitions $end\n#0\n0!\n'
    )
    out = run_cli(['list', str(write_vcd(tmp_path, text))]).stdout
    assert 'Matched: 2/2' in out


def test_minor_begin_beyond_eof_message(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd('$var wire 1 ! a $end\n', '#0\n0!\n#10\n1!\n'))
    r = run_cli(['search', '--begin', '999999', '--condition', 'a=1', str(p)])
    assert r.returncode != 0
    assert 'after the last event' in r.stderr
    assert 'end time must be' not in r.stderr


def test_minor_negative_limit_is_clean_error(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd('$var wire 1 ! a $end\n', '#0\n0!\n'))
    r = run_cli(['list', '--limit', '-3', str(p)])
    assert r.returncode != 0
    assert 'limit must be non-negative' in r.stderr and 'Traceback' not in r.stderr


def test_minor_limit_parse_error_is_distinct_type():
    assert va._LimitParseError is not va._TimeParseError
    assert issubclass(va._LimitParseError, ValueError)
