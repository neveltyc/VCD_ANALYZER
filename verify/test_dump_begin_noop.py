"""`dump --begin <T>` must agree with a full scan restricted to [T, end].

The value-change stream coalesces a record that merely re-asserts a signal's
current value: it is a no-op and adds no change event. That contract held for a
full scan but not for one starting mid-file, because the pre-`T` catch-up loop
advanced the bit-bus state without advancing the no-op baseline. A record at or
after `--begin` that re-asserted a pre-`--begin` value therefore looked like a
first observation, and `dump --begin` reported changes that the same file's
full scan correctly suppressed.

Re-assertions are routine, not exotic: iverilog emits a `$dumpall` checkpoint
that re-emits the current value of every signal in dump scope, so the divergence
was reachable from stock simulator output with no hand-written fixture.
"""
import contextlib
import io

import vcd_analyzer as va
from conftest import load_json_stdout, minimal_vcd, ns, write_vcd


# A constant signal, a vector, and a $dumpall checkpoint that re-emits both.
DUMPALL_VCD = minimal_vcd(
    '$var wire 1 ! stable $end\n'
    '$var wire 8 " data [7:0] $end\n',
    '#0\n0!\nb0 "\n'
    '#20\n1!\nb10101011 "\n'
    '#30\n$dumpall\n1!\nb10101011 "\n$end\n'
    '#40\n0!\n',
)

# Two bits of a bit-exploded bus, re-emitted unchanged by a checkpoint.
BUS_VCD = minimal_vcd(
    '$var wire 1 ^ ex [0] $end\n'
    '$var wire 1 _ ex [1] $end\n',
    '#0\n0^\n0_\n'
    '#20\n1^\n'
    '#30\n$dumpall\n1^\n0_\n$end\n'
    '#40\n1_\n',
)


def _dump_events(path, begin=None):
    v = va.VCDParser(str(path))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_dump(v, ns(json=True, limit=0, begin=begin))
    return [(e['time_ticks'], e['path'], e['value'])
            for e in load_json_stdout(buf.getvalue())['events']]


def _dump_text(path, begin=None):
    v = va.VCDParser(str(path))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_dump(v, ns(limit=0, begin=begin))
    return buf.getvalue()


# --- the reported bug -------------------------------------------------------

def test_dumpall_checkpoint_after_begin_is_not_a_change(tmp_path):
    p = write_vcd(tmp_path, DUMPALL_VCD)
    # stable has been 1 since 20ns and data has been 0xab since 20ns, so the
    # 30ns checkpoint re-asserts both and the 40ns fall is the only real change.
    assert _dump_events(p, '25ns') == [(40, 'tb.stable', '0')]


def test_begin_agrees_with_full_scan(tmp_path):
    p = write_vcd(tmp_path, DUMPALL_VCD)
    ts = va.VCDParser(str(p)).ts_sec
    full = _dump_events(p)
    assert len(full) == 5  # the two checkpoint records never appear at all
    for begin in ('0ns', '1ns', '20ns', '25ns', '30ns', '35ns', '40ns'):
        t0 = va.parse_time(begin, ts)
        assert _dump_events(p, begin) == [e for e in full if e[0] >= t0], begin


def test_bit_bus_checkpoint_after_begin_is_not_a_change(tmp_path):
    p = write_vcd(tmp_path, BUS_VCD)
    begin25 = _dump_events(p, '25ns')
    assert begin25 == [(40, 'tb.ex[1:0]', '3 (0x3)')]
    assert begin25 == [e for e in _dump_events(p) if e[0] >= 25]


def test_bit_bus_first_observation_after_begin_is_not_suppressed(tmp_path):
    # No bit has appeared before the window. The all-x template represents
    # unknown state, not a prior observation of the synthesized bus.
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! ex [0] $end\n'
        '$var wire 1 " ex [1] $end\n',
        '#0\n#10\nx!\n#20\n1"\n',
    ))
    full = _dump_events(p)
    assert full == [(10, 'tb.ex[1:0]', 'bxx'),
                    (20, 'tb.ex[1:0]', 'b1x')]
    assert _dump_events(p, '5ns') == full


def test_overwide_clamp_is_mirrored_across_the_boundary(tmp_path):
    # The catch-up baseline has to be clamped exactly as the emit path clamps it.
    # Skip that and a re-asserted over-wide value compares unequal to its own
    # stored form and leaks through the window edge as a change.
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 4 ! bus $end\n',
        '#0\nb11111 !\n#10\n$dumpall\nb11111 !\n$end\n#20\nb0000 !\n',
    ))
    full = _dump_events(p)
    assert full == [(0, 'tb.bus', 'bxxxx'), (20, 'tb.bus', '0 (0x0)')]
    assert _dump_events(p, '5ns') == [e for e in full if e[0] >= 5]


def test_noop_is_not_invented_in_text_mode_either(tmp_path):
    p = write_vcd(tmp_path, DUMPALL_VCD)
    text25 = _dump_text(p, '25ns')
    # Both windows skip the 30ns checkpoint and report only the 40ns fall.
    assert text25 == _dump_text(p, '35ns')
    assert 'T=40ns' in text25 and 'tb.stable' in text25
    assert 'T=30ns' not in text25          # the phantom header is gone
    assert '(no changes in range)' in _dump_text(p, '41ns')


# --- guards against over-suppression ----------------------------------------

def test_genuine_change_at_begin_boundary_still_emits(tmp_path):
    # 20ns is where stable and data actually change; a window that begins
    # exactly there must still report both.
    p = write_vcd(tmp_path, DUMPALL_VCD)
    assert _dump_events(p, '20ns') == [
        (20, 'tb.stable', '1'),
        (20, 'tb.data[7:0]', '171 (0xab)'),
        (40, 'tb.stable', '0'),
    ]


def test_first_observation_at_or_after_begin_still_emits(tmp_path):
    # A signal with no history before the window has no baseline to compare
    # against, so its first record is a genuine first observation, not a no-op.
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! early $end\n'
        '$var wire 1 " late $end\n',
        '#0\n0!\n#20\n1!\n#30\n1"\n#40\n0"\n',
    ))
    assert _dump_events(p, '25ns') == [
        (30, 'tb.late', '1'),
        (40, 'tb.late', '0'),
    ]


def test_event_triggers_still_count_each_record(tmp_path):
    # Event variables are markers, not levels: seeding the baseline must not
    # make repeated triggers at one value coalesce away.
    p = write_vcd(tmp_path, minimal_vcd(
        "$var event 1 ! trig $end\n",
        '#0\n1!\n#10\n1!\n#20\n1!\n#30\n1!\n',
    ))
    assert _dump_events(p, '15ns') == [(20, 'tb.trig', 'triggered'),
                                       (30, 'tb.trig', 'triggered')]


# --- a denser sweep over many window positions ------------------------------

def _sweep_text():
    """A stream that is mostly no-op re-assertions, across every record shape.

    Returns (vcd_text, value_change_records). Two of every three records repeat
    the current value, which is what a real $dumpall checkpoint looks like.
    """
    decls = ('$var wire 1 ! a $end\n'
             '$var wire 1 @ b $end\n'
             '$var wire 4 ~ nib [3:0] $end\n'
             '$var wire 1 ^ ex [0] $end\n'
             '$var wire 1 _ ex [1] $end\n'
             '$var wire 1 = ex [2] $end\n'
             '$var event 1 { trig $end\n'
             '$var wire 1 | late $end\n')
    lines = ['#0\n']
    n = 0
    bits = [0, 0, 0]
    a = b = '0'
    nib = '0000'
    for sym in ('!', '@'):
        lines.append('0{}\n'.format(sym))
        n += 1
    lines.append('b0000 ~\n')
    n += 1
    for sym, val in zip('^_=', bits):
        lines.append('{}{}\n'.format(val, sym))
        n += 1
    for k in range(1, 41):
        lines.append('#{}\n'.format(k * 10))
        if k % 3 == 0:
            a = '1' if a == '0' else '0'
        if k % 7 == 0:
            b = '1' if b == '0' else '0'
        if k % 5 == 0:
            nib = format((int(nib, 2) + 3) % 16, '04b')
        bits[k % 3] ^= 1
        lines.append('{}!\n{}@\nb{} ~\n'.format(a, b, nib))
        n += 3
        for j, sym in enumerate('^_='):
            lines.append('{}{}\n'.format(bits[j], sym))
            n += 1
        lines.append('1{\n')  # event trigger at every timestamp
        n += 1
        if k == 25:
            lines.append('1|\n')  # 'late' has no history before t=250
            n += 1
    return minimal_vcd(decls, ''.join(lines)), n


def test_sweep_begin_matches_full_scan_at_every_window_start(tmp_path):
    text, records = _sweep_text()
    p = write_vcd(tmp_path, text)
    full = _dump_events(p)
    # The fixture must actually exercise coalescing, or the equivalence below
    # would pass for a stream of nothing but real changes.
    assert len(full) < records, 'sweep fixture contains no no-op re-assertions'
    ts = va.VCDParser(str(p)).ts_sec
    for begin in ('0ns', '5ns', '100ns', '205ns', '250ns', '300ns', '399ns',
                  '400ns', '410ns'):
        t0 = va.parse_time(begin, ts)
        assert _dump_events(p, begin) == [e for e in full if e[0] >= t0], begin
