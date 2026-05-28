#!/usr/bin/env python3
"""Benchmark and equivalence harness for vcd_analyzer.

This is a developer tool, not a pytest test (pytest ignores it: the name is
not ``test_*``). It generates a deterministic synthetic VCD and times every
command on it.

Measurement notes
-----------------
Command output is sent to ``os.devnull`` (or a temp file), never captured
through a pipe into this process. Capturing megabytes of ``dump`` output via
``subprocess(capture_output=True)`` charges the parent's pipe-draining cost to
the command under test and inflates ``dump --limit 0`` by ~2x with high
run-to-run variance — measure the tool, not the harness.

Usage
-----
    python verify/bench.py                      # time the adjacent vcd_analyzer.py
    python verify/bench.py --big                # ~40 MB trace (heavier, slower)
    python verify/bench.py --steps 50000        # custom timestamp count
    python verify/bench.py --repeat 5           # best-of-5 instead of best-of-3
    python verify/bench.py --baseline OLD.py    # compare two copies + verify
                                                # their output is byte-identical
    python verify/bench.py --keep               # keep the generated .vcd

With ``--baseline`` the harness prints old/new/speedup columns and, separately,
hashes each command's real stdout for both copies and reports any divergence —
so a refactor that is "faster" but changes output is caught immediately.
"""

import argparse
import hashlib
import os
import random
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCRIPT = os.path.join(os.path.dirname(HERE), 'vcd_analyzer.py')


def _code(i):
    """Map an index to a short printable identifier_code (ASCII 33..126)."""
    s = ''
    i += 1
    while i > 0:
        i, r = divmod(i - 1, 94)
        s = chr(33 + r) + s
    return s


def generate_vcd(path, n_signals=400, n_buses=40, n_steps=200000, seed=1234):
    """Write a deterministic synthetic VCD.

    Mostly 1-bit signals (the common case) plus some multi-bit buses, a long
    time axis, and a $dumpvars initialization block — shaped to exercise the
    value-change hot path the way a real RTL dump does. Deterministic for a
    given seed so successive runs and baseline comparisons are stable.
    """
    rng = random.Random(seed)
    sigs = []  # (code, width)
    idx = 0
    with open(path, 'w') as f:
        f.write('$date today $end\n$version bench 1.0 $end\n$timescale 1ps $end\n')
        f.write('$scope module top $end\n')
        for i in range(n_signals):
            c = _code(idx); idx += 1
            sigs.append((c, 1))
            f.write(f'$var wire 1 {c} sig{i} $end\n')
        for i in range(n_buses):
            c = _code(idx); idx += 1
            w = rng.choice([8, 16, 32])
            sigs.append((c, w))
            f.write(f'$var wire {w} {c} bus{i} [{w - 1}:0] $end\n')
        f.write('$upscope $end\n$enddefinitions $end\n')
        f.write('#0\n$dumpvars\n')
        for c, w in sigs:
            f.write(f'0{c}\n' if w == 1 else f"b{'0' * w} {c}\n")
        f.write('$end\n')
        for t in range(1, n_steps):
            f.write(f'#{t * 10}\n')
            for _ in range(rng.randint(1, 12)):
                c, w = rng.choice(sigs)
                if w == 1:
                    f.write(f'{rng.randint(0, 1)}{c}\n')
                else:
                    bits = ''.join(rng.choice('01') for _ in range(w))
                    f.write(f'b{bits} {c}\n')


def cases(vcd):
    """Command lines exercising each command, keyed by a display label."""
    return {
        'info':              ['info', vcd],
        'list':              ['list', vcd],
        'summary (all)':     ['summary', vcd, '--limit', '0'],
        'summary (filter)':  ['summary', vcd, '--filter', 'sig0,sig1,bus0,bus1'],
        'dump (all,limit0)': ['dump', vcd, '--limit', '0'],
        'dump (filter)':     ['dump', vcd, '--filter', 'sig0,bus0', '--limit', '0'],
        'snapshot':          ['snapshot', vcd, '--at', '1ms'],
        'compare':           ['compare', vcd, '--at', '1ms,1.5ms'],
        'search (early)':    ['search', vcd, '--condition', 'sig0=1'],
        'search (full)':     ['search', vcd, '--condition', 'sig0=1', '--limit', '0'],
    }


def time_one(script, args, repeat):
    """Best-of-``repeat`` wall-clock seconds with stdout sent to os.devnull."""
    best = float('inf')
    with open(os.devnull, 'wb') as dn:
        for _ in range(repeat):
            t = time.perf_counter()
            r = subprocess.run([sys.executable, script, *args],
                               stdout=dn, stderr=subprocess.DEVNULL)
            best = min(best, time.perf_counter() - t)
            if r.returncode != 0:
                return None
    return best


def output_hash(script, args):
    """SHA-256 (truncated) of a command's real stdout+stderr, for equivalence."""
    r = subprocess.run([sys.executable, script, *args], capture_output=True)
    return hashlib.sha256(r.stdout + b'|RC=%d|' % r.returncode + r.stderr).hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser(description='Benchmark vcd_analyzer on a synthetic VCD.')
    ap.add_argument('--script', default=DEFAULT_SCRIPT,
                    help='vcd_analyzer.py to benchmark (default: the one next to verify/)')
    ap.add_argument('--baseline', default=None,
                    help='a second vcd_analyzer.py to compare against (old version)')
    ap.add_argument('--steps', type=int, default=None, help='number of timestamps')
    ap.add_argument('--big', action='store_true', help='~40 MB trace (overrides default steps)')
    ap.add_argument('--repeat', type=int, default=3, help='best-of-N timing (default 3)')
    ap.add_argument('--seed', type=int, default=1234, help='RNG seed for the generator')
    ap.add_argument('--keep', action='store_true', help='keep the generated VCD file')
    args = ap.parse_args()

    steps = args.steps if args.steps is not None else (1200000 if args.big else 200000)

    fd, vcd = tempfile.mkstemp(suffix='.vcd', prefix='vcd_bench_')
    os.close(fd)
    try:
        sys.stderr.write(f'Generating synthetic VCD ({steps:,} timestamps, seed {args.seed}) ...\n')
        generate_vcd(vcd, n_steps=steps, seed=args.seed)
        size = os.path.getsize(vcd)
        sys.stderr.write(f'  -> {vcd} ({size / 1e6:.1f} MB)\n\n')

        cs = cases(vcd)

        if args.baseline:
            print(f'{"case":20} {"baseline":>9} {"current":>9} {"speedup":>8}   out')
            print('-' * 62)
            for name, cmd in cs.items():
                old = time_one(args.baseline, cmd, args.repeat)
                new = time_one(args.script, cmd, args.repeat)
                if old is None or new is None:
                    print(f'{name:20} {"FAILED (nonzero exit)":>40}')
                    continue
                same = output_hash(args.baseline, cmd) == output_hash(args.script, cmd)
                spd = f'{old / new:.2f}x' if new > 0 else '-'
                print(f'{name:20} {old:8.3f}s {new:8.3f}s {spd:>8}   {"=" if same else "DIFF!"}')
            print('\n("=" means byte-identical stdout between baseline and current)')
        else:
            print(f'{"case":20} {"best":>9}   (of {args.repeat}, stdout->/dev/null)')
            print('-' * 44)
            for name, cmd in cs.items():
                best = time_one(args.script, cmd, args.repeat)
                print(f'{name:20} {best:8.3f}s' if best is not None
                      else f'{name:20} FAILED (nonzero exit)')
    finally:
        if args.keep:
            sys.stderr.write(f'\nKept VCD: {vcd}\n')
        else:
            os.unlink(vcd)


if __name__ == '__main__':
    main()
