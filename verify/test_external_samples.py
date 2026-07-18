from pathlib import Path
import json
import pytest
from conftest import run_cli

# name, min_signals, expected_time_max_ticks (None = don't assert)
SAMPLES = [
    ('external_sample_GordonMcGregor_sample.vcd', 5, 2010),
    ('external_sample_myhdl_simple_memory.vcd', 37, None),
    ('external_sample_vcs_empty_dump.vcd', 0, None),
]

@pytest.mark.parametrize('name,min_signals,time_max_ticks', SAMPLES)
def test_checked_in_external_samples_parse(name, min_signals, time_max_ticks):
    p = Path(__file__).resolve().parent / 'samples' / name
    if not p.exists():
        pytest.skip(f'{name} not bundled')
    info = run_cli(['--json', 'info', p])
    assert info.returncode == 0, info.stderr
    obj = json.loads(info.stdout)
    assert obj['signal_count'] >= min_signals
    # The GordonMcGregor sample indents every line by 4 spaces; the backward
    # t_max scan must tolerate leading whitespace instead of collapsing to
    # t_min (which used to yield 500ns ~ 500ns instead of 500ns ~ 2.01us).
    if time_max_ticks is not None:
        assert obj['time_max_ticks'] == time_max_ticks
    dump = run_cli(['--json', '--limit', '5', 'dump', p])
    assert dump.returncode == 0, dump.stderr
    assert 'events' in json.loads(dump.stdout)
