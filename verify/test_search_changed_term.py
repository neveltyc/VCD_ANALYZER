"""The `changed(SIG)` condition term (event mode).

`changed(SIG)` is an edge predicate: a clause containing one fires at exactly
the ticks where SIG transitions (a t=0 initialization and a signal's first
definition are not transitions) while the clause's level terms hold. Any
changed() term switches `search` to event mode; every OR clause must then
carry one. Two changed() terms in one clause require both signals to
transition at the same tick. With no --show, event mode defaults to showing
the changed() signals. The `--changed` flag is gone and points at this syntax.

Ported from the downstream rwave suite (tests/search_changed_condition.rs),
plus the per-record emission and order-independence cases specific to this
tool.
"""
import contextlib
import io

import pytest

import vcd_analyzer as va
from conftest import load_json_stdout, minimal_vcd, ns, run_cli, write_vcd


# Edge fixture under scope tb. Timeline (ns):
#   0    req=0 ack=0 ready=0 state=0   (initialization -- not a transition)
#   10   ready 0->1
#   15   req 0->1                       (ready=1)
#   20   req 1->0, ack 0->1             (both transition on one tick; ready=1)
#   30   req 0->1, ready 1->0           (settled: ready=0 at 30)
#   40   req 1->0, ack 1->0             (both transition again; ready=0)
#   50   state 0->5
DECLS = ('$var wire 1 ! req $end\n'
         '$var wire 1 # ack $end\n'
         '$var wire 1 % ready $end\n'
         '$var reg 8 & state $end\n')
DATA = ('#0\n0!\n0#\n0%\nb0 &\n'
        '#10\n1%\n'
        '#15\n1!\n'
        '#20\n0!\n1#\n'
        '#30\n1!\n0%\n'
        '#40\n0!\n0#\n'
        '#50\nb101 &\n')
# The same trace with the two records at #30 written in the other order. IEEE
# 1364 fixes neither the order nor the count of value_changes within one
# simulation_time, so this must not change any answer.
DATA_SWAPPED = DATA.replace('#30\n1!\n0%\n', '#30\n0%\n1!\n')


@pytest.fixture
def vcd(tmp_path):
    return write_vcd(tmp_path, minimal_vcd(DECLS, DATA))


def search(vcd_path, condition, **kw):
    v = va.VCDParser(str(vcd_path))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_search(v, ns(json=True, condition=condition,
                            begin='0ns', end='100ns', **kw))
    return load_json_stdout(buf.getvalue())


def times(res):
    return [e['time_ticks'] for e in res['events']]


# --- core semantics ---------------------------------------------------------

def test_standalone_changed_is_event_mode(vcd):
    # A lone changed(SIG) is a complete condition: one event per true
    # transition of req (15, 20, 30, 40), the t=0 init excluded, and --show
    # defaulting to the changed signal.
    res = search(vcd, ['changed(req)'])
    assert res['mode'] == 'event'
    assert times(res) == [15, 20, 30, 40]
    assert res['show'] == ['tb.req']
    assert res['changed'] == ['tb.req']


def test_changed_with_level_term_uses_the_ticks_settled_state(vcd):
    # At 30 req rises while ready falls on the same tick. Level terms read the
    # settled state, so `changed(req),ready=1` skips 30 and `,ready=0`
    # includes it.
    assert times(search(vcd, ['changed(req),ready=1'])) == [15, 20]
    assert times(search(vcd, ['changed(req),ready=0'])) == [30, 40]


def test_result_does_not_depend_on_intra_timestamp_record_order(tmp_path):
    # The bug this fixes: before 1.5.0 the level term was evaluated after each
    # record in turn, so merely swapping the two lines under #30 changed the
    # answer from 3 events to 2.
    a = write_vcd(tmp_path, minimal_vcd(DECLS, DATA), name='a.vcd')
    b = write_vcd(tmp_path, minimal_vcd(DECLS, DATA_SWAPPED), name='b.vcd')
    for cond in (['changed(req),ready=1'], ['changed(req),ready=0'],
                 ['changed(req)'], ['changed(req),changed(ack)']):
        assert search(a, cond) == search(b, cond), cond


def test_two_changed_terms_require_the_same_tick(vcd):
    # changed(req),changed(ack): both must transition on one tick -- 20 and 40.
    res = search(vcd, ['changed(req),changed(ack)'])
    assert times(res) == [20, 40]
    # Default --show is the union of the changed signals, path-sorted.
    assert res['show'] == ['tb.ack', 'tb.req']


def test_or_clauses_union_their_edges(vcd):
    # changed(req) OR changed(state): the union of both signals' transitions.
    res = search(vcd, ['changed(req)', 'changed(state)'])
    assert times(res) == [15, 20, 30, 40, 50]


def test_mixed_changed_and_level_clauses_rejected(vcd):
    with pytest.raises(va._ConditionParseError, match='cannot mix changed\\(\\)'):
        search(vcd, ['changed(req)', 'ready=1'])


def test_interval_mode_unaffected(vcd):
    # A level-only condition still yields intervals: ready=1 holds [10, 30).
    res = search(vcd, ['ready=1'])
    assert res['mode'] == 'interval'
    assert [(r['begin_ticks'], r['end_ticks']) for r in res['intervals']] == [(10, 30)]


# --- per-record emission (this tool's contract, finer than rwave's) ---------

def test_intra_timestamp_run_emits_each_transition(tmp_path):
    # A 0->1->0->1 run inside one timestamp exposes each transition, and the
    # shown value is the value AT that edge -- which is what keeps
    # `changed(s),s=1` meaning "rising edge of s".
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n', '#5\n0!\n#10\n1!\n0!\n1!\n#20\n0!\n'))
    assert times(search(p, ['changed(s)'])) == [10, 10, 10, 20]
    res = search(p, ['changed(s),s=1'])
    assert times(res) == [10, 10]
    assert [e['values']['tb.s'] for e in res['events']] == ['1', '1']


def test_intra_timestamp_toggle_still_shows_its_rising_edge(tmp_path):
    # A 0->1->0 run nets out to no change across the tick; the 0->1 edge inside
    # it is still a real edge and must not vanish (the 1.3.20 contract).
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n', '#5\n0!\n#10\n1!\n0!\n#20\n1!\n'))
    assert times(search(p, ['changed(s),s=1'])) == [10, 20]


def test_event_var_counts_each_trigger(tmp_path):
    # An event variable triggering several times in one timestamp emits one
    # event per trigger, consistent with dump's [10, 10, 20].
    p = write_vcd(tmp_path, minimal_vcd(
        '$var event 1 $ ev $end\n', '#10\n1$\n1$\n#20\n1$\n'))
    assert times(search(p, ['changed(ev)'])) == [10, 10, 20]


def test_level_term_on_event_variable_is_rejected(tmp_path):
    # An event variable has no level, so `ev=1` is a question about it that
    # cannot be answered; say so rather than return an empty result.
    p = write_vcd(tmp_path, minimal_vcd(
        '$var event 1 $ ev $end\n', '#10\n1$\n'))
    with pytest.raises(va._ConditionParseError, match=r'use changed\(tb\.ev\)'):
        search(p, ['ev=1'])


# --- syntax errors ----------------------------------------------------------

@pytest.mark.parametrize('cond,msg', [
    ('changed()', 'requires a signal'),
    ('changed(req)=1', 'takes no comparison'),
    ('changed(req,ack)', 'exactly one signal'),
    ('changed(req', 'exactly one signal'),
])
def test_malformed_changed_terms_error(vcd, cond, msg):
    with pytest.raises(va._ConditionParseError, match=msg):
        search(vcd, [cond])


def test_generic_condition_error_advertises_the_form(vcd):
    with pytest.raises(va._ConditionParseError, match=r'changed\(SIG\)'):
        search(vcd, ['req'])


def test_changed_prefix_is_case_insensitive_and_trims(vcd):
    assert times(search(vcd, ['Changed( tb.req )'])) == [15, 20, 30, 40]


# --- JSON shape and truncation ---------------------------------------------

def test_event_json_shape(vcd):
    res = search(vcd, ['changed(req),changed(ack)'])
    assert res['mode'] == 'event'
    # `changed` is an ARRAY of paths (it was a bare string before 1.5.0).
    assert res['changed'] == ['tb.ack', 'tb.req']
    assert res['condition'] == 'changed(req),changed(ack)'
    assert res['condition_resolved'] == 'changed(tb.req),changed(tb.ack)'


def test_event_mode_truncates_with_limit(vcd):
    res = search(vcd, ['changed(req)'], limit=2)
    assert res['shown'] == 2
    assert res['truncated'] is True
    assert res['total'] == 3 and res['total_is_exact'] is False
    assert '--limit' in res['hint']


# --- the removed flag -------------------------------------------------------

def test_changed_flag_is_gone_with_a_pointer(vcd):
    r = run_cli(['search', str(vcd), '--condition', 'a=1', '--changed', 'req'])
    assert r.returncode != 0
    assert '--condition "changed(req)"' in r.stderr
