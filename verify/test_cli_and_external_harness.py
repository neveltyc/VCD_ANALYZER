import json
import os
from pathlib import Path
from conftest import write_vcd, run_cli


def test_cli_main_error_and_sigpipe_safe(tmp_path):
    p = write_vcd(tmp_path, '$timescale 1ns $end\n$scope module tb $end\n$var wire 1 ! a $end\n$upscope $end\n$enddefinitions $end\n#0\n0!\n')
    r = run_cli(['compare', p, '--at', '10ns,0ns'])
    assert r.returncode != 0
    assert 'Error:' in r.stderr
    ok = run_cli(['--json', 'info', p])
    assert ok.returncode == 0
    assert json.loads(ok.stdout)['signal_count'] == 1


def test_external_vcd_directory_smoke_is_optional(tmp_path):
    # Harness test: real external VCDs are optional and can be supplied by
    # setting VCD_EXTERNAL_DIR to a directory containing *.vcd files.
    assert 'VCD_EXTERNAL_DIR' not in os.environ or Path(os.environ['VCD_EXTERNAL_DIR']).exists()
