from pathlib import Path
import json
import pytest
from conftest import run_cli

SAMPLES = [
    ('external_sample_GordonMcGregor_sample.vcd', 5),
    ('external_sample_myhdl_simple_memory.vcd', 37),
    ('external_sample_vcs_empty_dump.vcd', 0),
]

@pytest.mark.parametrize('name,min_signals', SAMPLES)
def test_checked_in_external_samples_parse(name, min_signals):
    p = Path(__file__).resolve().parent / 'samples' / name
    if not p.exists():
        pytest.skip(f'{name} not bundled')
    info = run_cli(['--json', 'info', p])
    assert info.returncode == 0, info.stderr
    obj = json.loads(info.stdout)
    assert obj['signal_count'] >= min_signals
    dump = run_cli(['--json', '--limit', '5', 'dump', p])
    assert dump.returncode == 0, dump.stderr
    assert 'events' in json.loads(dump.stdout)
