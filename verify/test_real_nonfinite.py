"""Non-finite real values (C99 %g 'inf' / '-inf' / 'nan') are legal IEEE 1364
real_number texts. Before the fix the parser rejected them, silently dropping
the whole value_change record: dump lost the event, info's time range
excluded the timestamp, summary under-counted — with no diagnostic. They are
now kept in the stream verbatim. Equality targets still reject them
(_parse_target_value), so no condition can match one — a stated limitation,
not data loss.
"""
import contextlib
import io

import vcd_analyzer as va
from conftest import load_json_stdout, minimal_vcd, ns, write_vcd


DECLS = ('$var real 64 % dac $end\n'
         '$var wire 1 ! clk $end\n')
DATA = ('#0\nr100 %\n1!\n'
        '#10\nrinf %\nrnan %\n'
        '#20\nr-inf %\n'
        '#30\nr3.5 %\n')


def _dump_json(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(DECLS, DATA))
    v = va.VCDParser(str(p))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_dump(v, ns(json=True, begin='0ns', end='40ns'))
    return load_json_stdout(buf.getvalue())


def test_dump_keeps_nonfinite_real_records(tmp_path):
    events = _dump_json(tmp_path)['events']
    dac = [(e['time_ticks'], e['value']) for e in events if e['path'] == 'tb.dac']
    assert dac == [(0, '100'), (10, 'inf'), (10, 'nan'), (20, '-inf'), (30, '3.5')]


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
    assert row['changes'] == 4
    assert row['unique'] == 5
    # Below the default cap the marker key is absent.
    assert 'unique_is_exact' not in row


def test_nonfinite_values_match_no_condition(tmp_path):
    # No equality target can name inf/nan, and a finite target simply never
    # compares equal to them: dac=5 finds only the 100 / 3.5 regions.
    p = write_vcd(tmp_path, minimal_vcd(DECLS, DATA))
    v = va.VCDParser(str(p))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_search(v, ns(json=True, condition=['dac=5'],
                            begin='0ns', end='40ns'))
    res = load_json_stdout(buf.getvalue())
    assert res['mode'] == 'interval'
    assert res['intervals'] == []
