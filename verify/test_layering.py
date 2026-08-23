"""Event/state layering (1.3.21): the parser exposes one change-semantics core
(_iter_changes) behind three distinct views — iter_events (raw per-change),
iter_transitions (adds prev + kind) and state_at/state_before/state_pair
(settled state) — with signal kind precomputed once (_event_sids/_sid_kind).

These lock the new internal API surface. Command-level output is proven
byte-identical to 1.3.20 by the existing suites and bench.py --baseline; here we
assert the layer boundaries directly.
"""
import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd


def _mk(tmp_path, decls, data):
    return va.VCDParser(str(write_vcd(tmp_path, minimal_vcd(decls, data))))


def _sid(v, path):
    return next(s for s, i in v.signals.items() if i['path'] == path)


DECLS = (
    "$var wire 1 ! clk $end\n"
    "$var wire 4 \" bus $end\n"
    "$var real 64 & temp $end\n"
    "$var event 1 % tick $end\n"
)


def test_sid_kind_and_event_sids(tmp_path):
    v = _mk(tmp_path, DECLS, "#0\n0!\nb0000 \"\nr1.5 &\n#10\n1!\n1%\n")
    assert v._sid_kind[_sid(v, 'tb.clk')] == 'scalar'
    assert v._sid_kind[_sid(v, 'tb.bus')] == 'vector'
    assert v._sid_kind[_sid(v, 'tb.temp')] == 'real'
    assert v._sid_kind[_sid(v, 'tb.tick')] == 'event'
    # _event_sids is the single source of truth for the no-op bypass.
    assert v._event_sids == frozenset({_sid(v, 'tb.tick')})


def test_synthesized_bus_kind_is_vector(tmp_path):
    v = _mk(tmp_path,
            "$var wire 1 ! d [0] $end\n$var wire 1 \" d [1] $end\n",
            "#0\n0!\n0\"\n#5\n1!\n1\"\n")
    gid = _sid(v, 'tb.d[1:0]')
    assert v.signals[gid].get('synthesized') is True
    assert v._sid_kind[gid] == 'vector'


def test_iter_transitions_prev_on_glitch(tmp_path):
    # clk 0 at t0, then 0->1->0 at t10 (leading 0 is a no-op re-assertion that
    # coalesces); prev tracks the value seen before each change.
    v = _mk(tmp_path, "$var wire 1 ! clk $end\n",
            "#0\n0!\n#10\n0!\n1!\n0!\n#20\n1!\n")
    sid = _sid(v, 'tb.clk')
    assert list(v.iter_transitions()) == [
        (0, sid, None, '0', 'scalar'),
        (10, sid, '0', '1', 'scalar'),
        (10, sid, '1', '0', 'scalar'),
        (20, sid, '0', '1', 'scalar'),
    ]


def test_event_var_counts_each_trigger(tmp_path):
    # An event marker fires three times at one timestamp: each is its own
    # transition (no no-op coalescing), kind == 'event'.
    v = _mk(tmp_path, "$var event 1 % tick $end\n", "#10\n1%\n1%\n1%\n")
    sid = _sid(v, 'tb.tick')
    assert list(v.iter_transitions()) == [
        (10, sid, None, '1', 'event'),
        (10, sid, '1', '1', 'event'),
        (10, sid, '1', '1', 'event'),
    ]


def test_iter_events_is_transitions_minus_prev_kind(tmp_path):
    # The public iter_events view is exactly the transition stream with prev and
    # kind projected out — the two layers agree by construction.
    v = _mk(tmp_path, DECLS, "#0\n0!\nb0000 \"\n#10\n0!\n1!\n0!\n1%\n1%\nb0101 \"\n#20\n1!\n")
    ev = list(v.iter_events())
    tr = list(v.iter_transitions())
    assert ev == [(t, s, val) for (t, s, _p, val, _k) in tr]
    # And filtering composes the same way through both views.
    sid = _sid(v, 'tb.clk')
    assert list(v.iter_events(sids={sid})) == \
        [(t, s, val) for (t, s, _p, val, _k) in v.iter_transitions(sids={sid})]


def test_state_at_settled_on_glitch(tmp_path):
    v = _mk(tmp_path, "$var wire 1 ! clk $end\n",
            "#0\n0!\n#10\n0!\n1!\n0!\n#20\n1!\n")
    sid = _sid(v, 'tb.clk')
    assert v.state_at(10) == {sid: '0'}      # settled end-of-t10 (glitch returns to 0)
    assert v.state_at(20) == {sid: '1'}
    assert v.state_before(10) == {sid: '0'}  # strictly before t10 == state_at(9)
    assert v.state_before(0) == {}


def test_state_pair_two_points(tmp_path):
    v = _mk(tmp_path, "$var wire 1 ! clk $end\n", "#0\n0!\n#10\n1!\n#20\n0!\n")
    sid = _sid(v, 'tb.clk')
    assert v.state_pair(5, 20) == ({sid: '0'}, {sid: '0'})
    assert v.state_pair(10, 15) == ({sid: '1'}, {sid: '1'})


def test_state_at_equivalent_to_folding_iter_events(tmp_path):
    # state_at is exactly a last-write-wins fold of the change stream.
    v = _mk(tmp_path, DECLS, "#0\n0!\nb0000 \"\nr1.5 &\n#10\n1!\nb0101 \"\nr2.5 &\n1%\n")
    for t_at in (0, 5, 10, 15):
        fold = {}
        for _t, sid, val in v.iter_events(0, t_at):
            fold[sid] = val
        assert v.state_at(t_at) == fold
