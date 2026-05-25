from types import SimpleNamespace
from pathlib import Path
import json
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / 'vcd_analyzer.py'


def write_vcd(tmp_path, text, name='t.vcd'):
    p = tmp_path / name
    p.write_text(text)
    return p


def minimal_vcd(decls, data, scope='tb', timescale='1ns'):
    return f"$timescale {timescale} $end\n$scope module {scope} $end\n" + decls + "$upscope $end\n$enddefinitions $end\n" + data


def ns(**kwargs):
    defaults = dict(json=False, verbose=False, limit=None, filter=None, begin=None, end=None, at=None,
                    condition=None, show=None, changed=None)
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def run_cli(args, timeout=20):
    return subprocess.run([sys.executable, '-S', str(SCRIPT)] + list(map(str, args)),
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout)


def load_json_stdout(text):
    return json.loads(text.strip())
