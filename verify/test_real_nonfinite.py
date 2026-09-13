"""Non-finite real values are legal IEEE 1364 real_number texts: C99 7.19.6.1
renders ±inf as 'inf' and NaN as 'nan' 'optionally followed by an
implementation-defined sequence of characters' (the MSVC CRT emits
'nan(snan)' / 'nan(ind)'), and IEEE 1364's real_number is %g output. Before
the fix the parser rejected them, silently dropping the whole value_change
record: dump lost the event, info's time range excluded the timestamp, summary
under-counted — with no diagnostic. They are now kept in the stream verbatim,
including the bounded nan(payload) form.

Condition semantics: no equality target can name non-finite values
(_parse_target_value rejects them; nan never compares equal), so '=' never
matches them; but '!=' with a finite target DOES match non-finite values
(nan/inf compare unequal to it) — locked by the tests below.
"""
import contextlib
import io

import vcd_analyzer as va
from conftest import load_json_stdout, minimal_vcd, ns, write_vcd


DECLS = ('$var real 64 % dac $end\n'
         '$var wire 1 ! clk $end\n')
DATA = ('#0\nr100 %\n1!\n'
        '#10\nrinf %\nrnan %\n'
        '#20\nr-inf %\nrnan(ind) %\n'
        '#30\nrNAN(IND) %\n'
        '#40\nr3.5 %\n')


def _dump_json(tmp_path, data=DATA, end='50ns'):
    p = write_vcd(tmp_path, minimal_vcd(DECLS, data))
    v = va.VCDParser(str(p))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_dump(v, ns(json=True, begin='0ns', end=end))
    return load_json_stdout(buf.getvalue())


def test_dump_keeps_nonfinite_real_records(tmp_path):
    events = _dump_json(tmp_path)['events']
    dac = [(e['time_ticks'], e['value']) for e in events if e['path'] == 'tb.dac']
    assert dac == [(0, '100'), (10, 'inf'), (10, 'nan'), (20, '-inf'),
                   (20, 'nan(ind)'), (30, 'NAN(IND)'), (40, '3.5')]


def test_info_time_range_includes_nonfinite_only_tail(tmp_path):
    # The final timestamp carries ONLY a non-finite real: before the fix it
    # was invisible to both iter_events and scan_time_range, so t_max
    # collapsed toward the last finite record.
    p = write_vcd(tmp_path, minimal_vcd(DECLS, '#0\nr100 %\n#10\nrinf %\n'))
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (0, 10)


def test_summary_counts_nonfinite_changes(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(DECLS, DATA))
    v = va.VCDParser(str(p))
    rows, _undef, counts = va._summary_rows(v, 0, None, None)
    row = next(r for r in rows if r['path'] == 'tb.dac')
    assert counts['active'] == 1
    # The t=0 record is the baseline (init), so 6 changes, 7 distinct values.
    assert row['changes'] == 6
    assert row['unique'] == 7
    # Below the default cap the marker key is absent.
    assert 'unique_is_exact' not in row


def test_malformed_nan_payloads_still_rejected(tmp_path):
    # A nan payload must be a single non-empty parenthesized group without
    # whitespace or nested parens: 'nan()' and 'nan(a b)' are not C99 %g
    # output and are dropped (the pre-payload-fix behavior for them).
    res = _dump_json(tmp_path, data='#0\nrnan() %\n#10\nrnan(a b) %\n',
                     end='20ns')
    assert res['events'] == []


def test_nonfinite_values_never_match_equality(tmp_path):
    # No equality target can name inf/nan, and a finite target never compares
    # equal to them: dac=5 matches none of the 7 records.
    p = write_vcd(tmp_path, minimal_vcd(DECLS, DATA))
    v = va.VCDParser(str(p))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_search(v, ns(json=True, condition=['dac=5'],
                            begin='0ns', end='50ns'))
    res = load_json_stdout(buf.getvalue())
    assert res['mode'] == 'interval'
    assert res['intervals'] == []


def test_nonfinite_values_match_inequality(tmp_path):
    # '!=' is `not equals` for reals (no unknown-protection applies): all 7
    # records, nan/inf included, compare unequal to 5, so the condition holds
    # across the whole window (last value 3.5 still != 5 at t1=50).
    p = write_vcd(tmp_path, minimal_vcd(DECLS, DATA))
    v = va.VCDParser(str(p))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_search(v, ns(json=True, condition=['dac!=5'],
                            begin='0ns', end='50ns'))
    res = load_json_stdout(buf.getvalue())
    assert res['mode'] == 'interval'
    assert res['total'] == 1
    assert res['intervals'] == [{
        'begin_ticks': 0, 'begin_h': '0s', 'end_ticks': 50, 'end_h': '50ns'}]
