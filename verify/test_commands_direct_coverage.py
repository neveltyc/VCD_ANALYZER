import json
import pytest
import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd, ns, load_json_stdout


def make_axi_vcd(tmp_path):
    text = minimal_vcd('''$var wire 1 ! valid $end
$var wire 1 " ready $end
$var wire 8 # data $end
$var event 1 $ ev $end
''', '''$dumpvars
0!
0"
b00000000 #
$end
#5
1"
#10
1!
b00001010 #
#15
b00001011 #
#20
0!
#30
1$
#40
1$
''')
    return write_vcd(tmp_path, text)


def test_cmd_info_list_dump_summary_snapshot_compare_direct(tmp_path, capsys):
    p = make_axi_vcd(tmp_path)
    v = va.VCDParser(str(p))

    va.cmd_info(v, ns(json=True))
    info = load_json_stdout(capsys.readouterr().out)
    assert info['signal_count'] == 4
    assert info['time_max_ticks'] == 40

    va.cmd_list(v, ns(json=False, filter='*data', limit=10))
    out = capsys.readouterr().out
    assert 'tb.data' in out

    va.cmd_dump(v, ns(json=True, begin='10ns', end='15ns', filter='data', limit=10))
    dump = load_json_stdout(capsys.readouterr().out)
    assert [e['value'] for e in dump['events']] == ['10 (0x0a)', '11 (0x0b)']

    va.cmd_summary(v, ns(json=True, begin='0ns', end='20ns', filter='valid,data', verbose=True))
    summary = load_json_stdout(capsys.readouterr().out)
    assert summary['selected'] == 2
    assert summary['active'] >= 1

    va.cmd_snapshot(v, ns(json=True, at='15ns', filter='data,valid'))
    snap = load_json_stdout(capsys.readouterr().out)
    vals = {r['path']: r['value'] for r in snap['signals']}
    assert vals['tb.data'] == '11 (0x0b)'
    assert vals['tb.valid'] == '1'

    va.cmd_compare(v, ns(json=True, at='10ns,20ns', filter='valid'))
    comp = load_json_stdout(capsys.readouterr().out)
    assert comp['total'] == 1
    assert comp['diffs'][0]['at_t1'] == '1'
    assert comp['diffs'][0]['at_t2'] == '0'


def test_cmd_search_interval_segment_event_direct(tmp_path, capsys):
    p = make_axi_vcd(tmp_path)
    v = va.VCDParser(str(p))

    va.cmd_search(v, ns(json=True, condition='valid=1', limit=10))
    intervals = load_json_stdout(capsys.readouterr().out)
    assert intervals['mode'] == 'interval'
    assert intervals['intervals'][0]['begin_ticks'] == 10
    assert intervals['intervals'][0]['end_ticks'] == 20

    va.cmd_search(v, ns(json=True, condition='valid=1', show='data', limit=10))
    segs = load_json_stdout(capsys.readouterr().out)
    assert segs['mode'] == 'segment'
    assert [s['values']['tb.data'] for s in segs['segments']] == ['10 (0x0a)', '11 (0x0b)']

    va.cmd_search(v, ns(json=True, condition='changed(data),valid=1', show='data,valid', limit=10))
    ev = load_json_stdout(capsys.readouterr().out)
    assert ev['mode'] == 'event'
    assert [e['time_ticks'] for e in ev['events']] == [10, 15]

    va.cmd_search(v, ns(json=True, condition='changed(ev)', limit=10))
    ev2 = load_json_stdout(capsys.readouterr().out)
    assert [e['time_ticks'] for e in ev2['events']] == [30, 40]


def test_command_error_paths_direct(tmp_path):
    p = make_axi_vcd(tmp_path)
    v = va.VCDParser(str(p))
    with pytest.raises(va._TimeParseError):
        va.cmd_dump(v, ns(begin='20ns', end='10ns'))
    with pytest.raises(va._TimeParseError):
        va.cmd_summary(v, ns(begin='20ns', end='10ns'))
    with pytest.raises(va._TimeParseError):
        va.cmd_compare(v, ns(at='20ns,10ns'))
    with pytest.raises(va._ConditionParseError):
        va.cmd_search(v, ns(condition='valid=1,ready=1', show='missing'))
    with pytest.raises(va._ConditionParseError):
        va.cmd_search(v, ns(condition='v=1'))  # ambiguous substring valid/ev


def test_search_empty_vcd_error(tmp_path):
    p = write_vcd(tmp_path, '$timescale 1ns $end\n$scope module tb $end\n$var wire 1 ! a $end\n$upscope $end\n$enddefinitions $end\n')
    v = va.VCDParser(str(p))
    with pytest.raises(va._ConditionParseError):
        va.cmd_search(v, ns(condition='a=1'))


def test_dump_every_value_change_in_order(tmp_path, capsys):
    # dump promises "every value change in a time window, in order": several
    # changes to one signal at the same timestamp are all shown.
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n',
        '#10\n0!\n1!\n0!\n#20\n1!\n'))
    v = va.VCDParser(str(p))
    va.cmd_dump(v, ns(json=False, limit=0))
    out = capsys.readouterr().out
    # Text rows are '  <path padded> = <value>'.
    rows = [l for l in out.splitlines() if ' = ' in l]
    vals = [r.split(' = ')[1].strip() for r in rows]
    assert vals == ['0', '1', '0', '1']
    assert all('tb.s' in r for r in rows)


def test_summary_counts_intra_timestamp_transitions(tmp_path, capsys):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n',
        '#10\n0!\n1!\n0!\n#20\n1!\n'))
    v = va.VCDParser(str(p))
    va.cmd_summary(v, ns(json=True, begin='0ns', end='30ns'))
    r = load_json_stdout(capsys.readouterr().out)
    row = r['rows'][0]
    # undef->0, 0->1, 1->0, 0->1
    assert row['changes'] == 4
    assert row['rise_count'] == 2
    assert row['fall_count'] == 1


def test_search_changed_detects_intra_timestamp_edge(tmp_path, capsys):
    # A 0->1->0 run within one timestamp must not make the 0->1 edge vanish:
    # the pre-1.3.20 per-timestamp dict coalesced the run to a net 0->0 "no
    # change". With ordered events, each intra-timestamp transition is
    # evaluated individually; the 0->1 at #10 satisfies s=1 (post-change)
    # even though the group net is 0->0.
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n',
        '#5\n0!\n#10\n1!\n0!\n#20\n1!\n'))
    v = va.VCDParser(str(p))
    va.cmd_search(v, ns(json=True, condition='changed(s),s=1',
                        begin='0ns', end='30ns', limit=0))
    r = load_json_stdout(capsys.readouterr().out)
    assert [e['time_ticks'] for e in r['events']] == [10, 20]


def test_event_var_counts_each_trigger(tmp_path, capsys):
    # Event value_changes are markers: every record triggers, so the
    # no-op-reassertion suppression that applies to level signals must not
    # swallow repeated event markers (the pre-1.3.20 dumpall regression was
    # specifically about event vars counting each trigger).
    p = write_vcd(tmp_path, minimal_vcd(
        '$var event 1 $ ev $end\n',
        '#10\n1$\n1$\n#20\n1$\n'))
    v = va.VCDParser(str(p))
    va.cmd_dump(v, ns(json=True, limit=0))
    r = load_json_stdout(capsys.readouterr().out)
    assert [e['time_ticks'] for e in r['events']] == [10, 10, 20]
    assert all(e['value'] == 'triggered' for e in r['events'])


def test_search_changed_event_var_counts_each_trigger(tmp_path, capsys):
    # search --changed must agree with dump: an event var triggering several
    # times in one timestamp emits one event per trigger, not one per
    # timestamp ("VCD event vars count each trigger").
    p = write_vcd(tmp_path, minimal_vcd(
        '$var event 1 $ ev $end\n',
        '#10\n1$\n1$\n#20\n1$\n'))
    v = va.VCDParser(str(p))
    va.cmd_search(v, ns(json=True, condition='changed(ev)',
                        begin='0ns', end='30ns', limit=0))
    r = load_json_stdout(capsys.readouterr().out)
    assert [e['time_ticks'] for e in r['events']] == [10, 10, 20]


def test_search_changed_level_signal_multiple_matches_per_timestamp(tmp_path, capsys):
    # A level signal can satisfy the condition on more than one transition in
    # the same timestamp: 0->1->0->1 with condition s=1 matches both rising
    # steps at #10, so search emits #10 twice (one per matching transition),
    # consistent with dump's "count each change".
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n',
        '#5\n0!\n#10\n1!\n0!\n1!\n#20\n0!\n'))
    v = va.VCDParser(str(p))
    va.cmd_search(v, ns(json=True, condition='changed(s),s=1',
                        begin='0ns', end='30ns', limit=0))
    r = load_json_stdout(capsys.readouterr().out)
    assert [e['time_ticks'] for e in r['events']] == [10, 10]


def test_snapshot_semantics_last_write_wins(tmp_path, capsys):
    # Snapshot reports state at a time: last write within the timestamp wins.
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n',
        '#10\n0!\n1!\n0!\n'))
    v = va.VCDParser(str(p))
    va.cmd_snapshot(v, ns(json=True, at='10ns'))
    r = load_json_stdout(capsys.readouterr().out)
    assert r['known'] == 1
    assert r['signals'][0]['value'] == '0'


def test_info_rejects_negative_limit(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd('$var wire 1 ! s $end\n', '#0\n1!\n'))
    v = va.VCDParser(str(p))
    with pytest.raises(va._LimitParseError):
        va.cmd_info(v, ns(json=False, limit=-5))


def test_info_empty_data_text_has_no_none(tmp_path, capsys):
    p = write_vcd(tmp_path, minimal_vcd('$var wire 1 ! s $end\n', ''))
    v = va.VCDParser(str(p))
    va.cmd_info(v, ns(json=False))
    out = capsys.readouterr().out
    assert 'None ~ None' not in out
    assert '(no data in file)' in out
