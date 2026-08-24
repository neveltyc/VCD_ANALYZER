"""Condition matching is decided by a signal's declared kind, not by sniffing
the characters of its value, and a target that no signal could carry is
rejected rather than kept as a never-equal literal.

Before 1.5.0 a real signal's %g text was read as a bit string, so a real
valued 100.0 (dumped as `r100`) matched `dac=4` (binary 100 == 4) and missed
`dac=100`. Both a false positive and a false negative on the same signal.
"""
import contextlib
import io

import pytest

import vcd_analyzer as va
from conftest import load_json_stdout, minimal_vcd, ns, write_vcd


DECLS = ('$var real 64 ! dac $end\n'
         '$var reg 8 " state $end\n'
         '$var event 1 # ev $end\n')
DATA = ('#0\nr100 !\nb0 "\n'
        '#10\nr3.5 !\nb101 "\n1#\n'
        '#20\nr0 !\nb0 "\n')


@pytest.fixture
def vcd(tmp_path):
    return write_vcd(tmp_path, minimal_vcd(DECLS, DATA))


def search(vcd_path, condition, **kw):
    v = va.VCDParser(str(vcd_path))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_search(v, ns(json=True, condition=condition,
                            begin='0ns', end='30ns', **kw))
    return load_json_stdout(buf.getvalue())


def spans(res):
    return [(r['begin_ticks'], r['end_ticks']) for r in res['intervals']]


# --- real signals -----------------------------------------------------------

def test_real_no_longer_matches_its_value_read_as_bits(vcd):
    # The false positive: `dac=4` matched because int("100", 2) == 4.
    assert spans(search(vcd, ['dac=4'])) == []


def test_real_matches_its_actual_value(vcd):
    # The false negative: the real IS 100 from 0 until it changes at 10.
    assert spans(search(vcd, ['dac=100'])) == [(0, 10)]


def test_real_matches_a_fractional_target(vcd):
    assert spans(search(vcd, ['dac=3.5'])) == [(10, 20)]


def test_real_decimal_and_real_targets_agree(vcd):
    assert spans(search(vcd, ['dac=0'])) == spans(search(vcd, ['dac=0.0']))


def test_real_ne_is_the_negation_of_eq(vcd):
    assert spans(search(vcd, ['dac!=100'])) == [(10, 30)]


def test_real_cannot_be_compared_against_a_bit_pattern(vcd):
    with pytest.raises(va._ConditionParseError, match='against a bit pattern'):
        search(vcd, ['dac=b1x0'])


def test_logic_signal_cannot_be_compared_against_a_real_number(vcd):
    with pytest.raises(va._ConditionParseError, match='against the real number'):
        search(vcd, ['state=3.14'])


def test_logic_matching_is_unchanged(vcd):
    # The bits path is untouched: decimal, hex and binary all name the same
    # 8-bit value, and a 4-state pattern still matches width-aware.
    for target in ('state=5', 'state=0x5', 'state=b101'):
        assert spans(search(vcd, [target])) == [(10, 20)], target


# --- event variables --------------------------------------------------------

def test_level_term_on_event_variable_points_at_changed(vcd):
    with pytest.raises(va._ConditionParseError, match=r'use changed\(tb\.ev\)'):
        search(vcd, ['ev=1'])


# --- target grammar ---------------------------------------------------------

@pytest.mark.parametrize('cond', [
    'state=1 OR dac=1',     # a mis-typed in-string OR
    'state=1|dac=1',
    'state=IDLE',           # a symbolic name the tool cannot resolve
    'state=nan',
    'state=inf',
])
def test_unusable_targets_are_rejected_not_silently_unmatched(vcd, cond):
    # Each of these previously parsed as an opaque literal target that could
    # only ever compare unequal, so the command reported a confident "no
    # match" for a question it never actually asked.
    with pytest.raises(va._ValueParseError, match='invalid target'):
        search(vcd, [cond])


def test_rejection_message_names_the_or_spelling(vcd):
    with pytest.raises(va._ValueParseError, match='repeat --condition'):
        search(vcd, ['state=1 OR dac=1'])
