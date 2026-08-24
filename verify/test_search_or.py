"""OR-of-ANDs conditions: repeating --condition unions the clauses.

Each --condition is one comma-separated AND clause; repeating the flag ORs
them, and the search holds wherever *any* clause holds. The canonical use is
multi-channel protocols -- one clause per channel to find when any channel
handshakes -- with no in-string boolean syntax.

Ported from the downstream rwave suite (tests/search_or_conditions.rs), plus
the argparse-level cases specific to this tool.
"""
import pytest

import vcd_analyzer as va
from conftest import load_json_stdout, minimal_vcd, ns, run_cli, write_vcd


# Two channels and an error flag under scope tb. Timeline (ns):
#   10..20  ch0 handshake (ch0_valid=ch0_ready=1), data steps aa -> bb at 15
#   30..40  ch1 handshake (ch1_valid=ch1_ready=1), data steps cc -> dd at 35
#   50..60  err=1
#   70..80  state=5
DECLS = (
    '$var wire 1 ! ch0_valid $end\n'
    '$var wire 1 " ch0_ready $end\n'
    '$var wire 1 # ch1_valid $end\n'
    '$var wire 1 $ ch1_ready $end\n'
    '$var wire 1 % err $end\n'
    '$var reg 8 & data $end\n'
    '$var reg 8 \' state $end\n'
)
DATA = (
    "#0\n0!\n0\"\n0#\n0$\n0%\nb0 &\nb0 '\n"
    '#5\nb10101010 &\n'
    '#10\n1!\n1"\n'
    '#15\nb10111011 &\n'
    '#20\n0!\n0"\n'
    '#25\nb11001100 &\n'
    '#30\n1#\n1$\n'
    '#35\nb11011101 &\n'
    '#40\n0#\n0$\n'
    '#50\n1%\n'
    '#60\n0%\n'
    "#70\nb101 '\n"
    "#80\nb0 '\n"
)

CH0 = 'ch0_valid=1,ch0_ready=1'
CH1 = 'ch1_valid=1,ch1_ready=1'


@pytest.fixture
def vcd(tmp_path):
    return write_vcd(tmp_path, minimal_vcd(DECLS, DATA))


def search(vcd_path, condition, **kw):
    """Run cmd_search under --json and return the parsed result."""
    import io
    import contextlib
    v = va.VCDParser(str(vcd_path))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_search(v, ns(json=True, condition=condition,
                            begin='0ns', end='100ns', **kw))
    return load_json_stdout(buf.getvalue())


def spans(res):
    key = 'segments' if res['mode'] == 'segment' else 'intervals'
    return [(r['begin_ticks'], r['end_ticks']) for r in res[key]]


# --- union semantics --------------------------------------------------------

def test_each_clause_alone_yields_only_its_own_window(vcd):
    assert spans(search(vcd, [CH0])) == [(10, 20)]
    assert spans(search(vcd, [CH1])) == [(30, 40)]


def test_or_interval_is_union_of_clauses(vcd):
    # Neither single clause produces both windows; the OR does. Union, not
    # intersection.
    assert spans(search(vcd, [CH0, CH1])) == [(10, 20), (30, 40)]
    assert spans(search(vcd, [CH0, CH1, 'err=1'])) == [(10, 20), (30, 40), (50, 60)]


def test_or_clause_can_use_ne_independently(vcd):
    # != semantics are per-clause and unchanged.
    assert spans(search(vcd, [CH0, 'err!=0'])) == [(10, 20), (50, 60)]


def test_or_segment_mode_splits_within_union_windows(vcd):
    # In segment mode the union windows are split by the observed --show value:
    # data steps once inside each handshake, so each window yields two segments.
    res = search(vcd, ['ch0_valid=1', 'ch1_valid=1'], show='data')
    assert res['mode'] == 'segment'
    assert spans(res) == [(10, 15), (15, 20), (30, 35), (35, 40)]


def test_or_event_mode_fires_per_clause(vcd):
    # data changes at 15 (inside ch0's handshake) and 35 (inside ch1's):
    # one event enabled by each clause.
    res = search(vcd, ['changed(data),' + CH0, 'changed(data),' + CH1])
    assert res['mode'] == 'event'
    assert [e['time_ticks'] for e in res['events']] == [15, 35]


def test_or_limit_caps_merged_results(vcd):
    capped = search(vcd, [CH0, CH1, 'err=1'], limit=2)
    assert capped['shown'] == 2 and capped['truncated'] is True
    assert capped['total_is_exact'] is False
    assert search(vcd, [CH0, CH1, 'err=1'], limit=0)['shown'] == 3


def test_cost_scales_with_signals_not_clauses(vcd):
    # Three clauses over five distinct signals load five signals, not fifteen:
    # the selection is the union of the clauses' signals.
    v = va.VCDParser(str(vcd))
    clauses = va._resolve_clauses(v, [CH0, CH1, 'err=1'])
    selected = {c['sid'] for cl in clauses for c in cl}
    assert len(selected) == 5


# --- condition echo ---------------------------------------------------------

def test_single_clause_echo_has_no_parens(vcd):
    res = search(vcd, [CH0])
    assert res['condition'] == CH0
    assert res['condition_resolved'] == 'tb.ch0_valid=1,tb.ch0_ready=1'


def test_multi_clause_echo_is_parenthesized_or(vcd):
    res = search(vcd, [CH0, 'err=1'])
    assert res['condition'] == '({}) OR (err=1)'.format(CH0)
    assert res['condition_resolved'] == (
        '(tb.ch0_valid=1,tb.ch0_ready=1) OR (tb.err=1)')


# --- clause de-duplication --------------------------------------------------

def test_identical_clauses_fold_to_one(vcd):
    assert search(vcd, ['ch0_valid=1', 'ch0_valid=1'])['condition'] == 'ch0_valid=1'


def test_term_order_permuted_clauses_fold_keeping_the_first(vcd):
    res = search(vcd, [CH0, 'ch0_ready=1,ch0_valid=1'])
    assert res['condition'] == CH0


def test_alias_equivalent_clauses_fold(vcd):
    # A different spelling of a path resolving to the same signal folds.
    res = search(vcd, ['ch0_valid=1', 'tb.ch0_valid=1'])
    assert res['condition'] == 'ch0_valid=1'


def test_different_base_clauses_are_not_folded(vcd):
    # 5 and 0x5 are the same number but different spellings: no cross-base
    # normalization, so both clauses are kept -- and both match one window.
    res = search(vcd, ['state=5', 'state=0x5'])
    assert res['condition'] == '(state=5) OR (state=0x5)'
    assert spans(res) == [(70, 80)]


# --- error paths ------------------------------------------------------------

def test_empty_clause_errors(vcd):
    with pytest.raises(va._ConditionParseError, match='requires --condition'):
        search(vcd, [''])


def test_bad_term_errors(vcd):
    # A term missing its value fails the whole command, as before OR existed.
    with pytest.raises(va._ConditionParseError, match='invalid condition'):
        search(vcd, ['ch0_valid='])


@pytest.mark.parametrize('cond', ['ch0_valid=1 OR ch1_valid=1',
                                  'ch0_valid=1|ch1_valid=1'])
def test_in_string_or_is_not_an_operator(vcd, cond):
    # OR / | inside a --condition string are ordinary text, not operators, and
    # produce a parse error rather than a plausible-looking empty result.
    with pytest.raises(va._ValueParseError, match='invalid target'):
        search(vcd, [cond])


def test_ambiguous_clause_still_errors(vcd):
    # The per-term unique-resolution requirement is not relaxed by OR.
    with pytest.raises(va._ConditionParseError, match='matches 2 signals'):
        search(vcd, ['ch0_valid=1', 'ch0=1'])


# --- CLI level (argparse) ---------------------------------------------------

def test_cli_repeated_condition_ors_instead_of_overwriting(vcd):
    # Before 1.5.0 argparse silently kept only the LAST --condition, so this
    # invocation answered a different question than it asked.
    r = run_cli(['--json', 'search', str(vcd), '--condition', CH0,
                 '--condition', CH1, '--begin', '0ns', '--end', '100ns'])
    assert r.returncode == 0, r.stderr
    res = load_json_stdout(r.stdout)
    assert spans(res) == [(10, 20), (30, 40)]


def test_cli_missing_condition_still_errors(vcd):
    r = run_cli(['search', str(vcd)])
    assert r.returncode != 0
    assert '--condition' in r.stderr
