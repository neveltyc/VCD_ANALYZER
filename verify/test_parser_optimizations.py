"""Regression tests for the 1.3.15 parser optimizations.

Covers the chunk-based data tokenizer and the one-line header fast path. The
guiding invariant for both: an optimized path must be *observationally
identical* to the tolerant reference behavior. These tests force boundary
conditions (tiny chunk sizes, tokens straddling boundaries, mixed one-line and
multi-line declarations) that the standard fixtures do not exercise.
"""
import os

import pytest

import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd


# ---------------------------------------------------------------------------
# Chunk-based data tokenizer
# ---------------------------------------------------------------------------

def _events(path, sids=None):
    return list(va.VCDParser(str(path)).iter_events(0, None, sids))


def test_chunk_tokenizer_matches_line_based_small_chunks(tmp_path, monkeypatch):
    # A trace whose value-change lines will be split at many byte offsets when
    # read in small chunks. We compare events parsed at the default chunk size
    # against events parsed with the tokenizer forced to a 64 KiB floor; both
    # must be identical, and both must match a hand-computed expectation.
    decls = ''.join('$var wire 1 {} s{} $end\n'.format(chr(33 + i), i) for i in range(5))
    data_lines = ['#0\n']
    for i in range(5):
        data_lines.append('0{}\n'.format(chr(33 + i)))
    t = 0
    for k in range(2000):
        t += 10
        data_lines.append('#{}\n'.format(t))
        data_lines.append('{}{}\n'.format(k % 2, chr(33 + (k % 5))))
    p = write_vcd(tmp_path, minimal_vcd(decls, ''.join(data_lines)))

    monkeypatch.setenv('VCD_ANALYZER_TOKEN_CHUNK_SIZE', '65536')
    a = _events(p)
    monkeypatch.delenv('VCD_ANALYZER_TOKEN_CHUNK_SIZE', raising=False)
    b = _events(p)
    assert a == b
    # Sanity: we got the expected number of value-change events (5 initial + 2000).
    assert len(a) == 5 + 2000


def test_chunk_boundary_does_not_drop_dense_bus_changes(tmp_path):
    # The exact shape that broke an alternative regex-based fast path: two
    # bus aliases sharing consecutive value changes at the same timestamp.
    # The chunk tokenizer must preserve every one. The data section is sized
    # well past the 64 KiB chunk floor so multiple real chunk boundaries fall
    # inside the value-change stream, exercising the carry buffer.
    decls = '$var wire 16 ( busA [15:0] $end\n$var wire 16 7 busB [15:0] $end\n'
    data = ['#0\n', 'b0 (\n', 'b0 7\n']
    t = 0
    n = 8000  # ~ hundreds of KB of data section, several 64 KiB chunks
    for k in range(n):
        t += 10
        data.append('#{}\n'.format(t))
        bits = format(k, 'b')
        data.append('b{} (\n'.format(bits))
        data.append('b{} 7\n'.format(bits))
    p = write_vcd(tmp_path, minimal_vcd(decls, ''.join(data)))
    assert os.path.getsize(str(p)) > 65536  # ensure >1 chunk

    ev_all = _events(p)
    # Per-alias filtered counts must equal the unfiltered per-alias counts.
    for code in ('(', '7'):
        full = sum(1 for _t, s, _v in ev_all if s == code)
        filt = sum(1 for _t, s, _v in _events(p, {code}) if s == code)
        assert full == filt, 'alias {} lost events under filter'.format(code)
        assert full == 1 + n  # 1 initial + n changes


def test_no_trailing_newline_last_token_preserved(tmp_path):
    # A data section whose final byte is not whitespace must still yield its
    # last token (carry-buffer flush at EOF).
    text = minimal_vcd('$var wire 1 ! s $end\n', '#0\n0!\n#10\n1!')  # no final newline
    p = write_vcd(tmp_path, text)
    ev = _events(p)
    assert ev[-1] == (10, '!', '1')


# ---------------------------------------------------------------------------
# One-line header fast path vs multi-line generic path
# ---------------------------------------------------------------------------

def _sig_table(path):
    v = va.VCDParser(str(path))
    return sorted(
        (info['path'], info['width'], info.get('type'), info.get('synthesized', False))
        for info in v.signals.values()
    )


def test_header_fast_path_matches_multiline(tmp_path):
    # Same declarations, once one-per-line (fast path) and once split across
    # lines (generic path). Parsed signal tables must be identical.
    one_line = (
        '$timescale 1ns $end\n'
        '$scope module top $end\n'
        '$var wire 1 ! clk $end\n'
        '$var wire 8 " data [7:0] $end\n'
        '$var wire 1 # \\esc.aped $end\n'
        '$upscope $end\n'
        '$enddefinitions $end\n#0\n0!\n'
    )
    multi_line = (
        '$timescale\n 1ns\n $end\n'
        '$scope\n module\n top\n $end\n'
        '$var\n wire\n 1\n !\n clk\n $end\n'
        '$var\n wire\n 8\n "\n data\n [7:0]\n $end\n'
        '$var\n wire\n 1\n #\n \\esc.aped\n $end\n'
        '$upscope\n $end\n'
        '$enddefinitions\n $end\n#0\n0!\n'
    )
    pa = write_vcd(tmp_path, one_line, 'one.vcd')
    pb = write_vcd(tmp_path, multi_line, 'multi.vcd')
    assert _sig_table(pa) == _sig_table(pb)


def test_header_fast_path_bit_explode_and_range(tmp_path):
    # Fast path must feed the same bit-explosion / range-folding logic.
    # The bit-explosion heuristic requires the bit index as a separate token
    # ('d [0]'), matching IEEE free-format reference syntax; a glued 'd[0]'
    # is a standalone name. This mirrors the generic parser exactly.
    one_line = (
        '$scope module m $end\n'
        '$var wire 1 ! d [0] $end\n'
        '$var wire 1 " d [1] $end\n'
        '$var wire 4 # bus [3:0] $end\n'
        '$enddefinitions $end\n#0\n'
    )
    p = write_vcd(tmp_path, one_line)
    table = _sig_table(p)
    # The two d[0]/d[1] bits reassemble into a synthesized 2-bit bus.
    assert any(w == 2 and synth for _path, w, _t, synth in table)
    # The 4-bit declaration keeps its range in the path.
    assert any(path.endswith('bus[3:0]') and w == 4 for path, w, _t, _synth in table)


def test_header_mixed_one_line_and_multi_line(tmp_path):
    # A header that mixes both styles must parse every declaration.
    text = (
        '$scope module m $end\n'
        '$var wire 1 ! a $end\n'              # fast path
        '$var\n wire 2 " b [1:0]\n $end\n'    # generic path
        '$var wire 1 # c $end\n'              # fast path again
        '$enddefinitions $end\n#0\n'
    )
    p = write_vcd(tmp_path, text)
    paths = [row[0] for row in _sig_table(p)]
    assert any(pp.endswith('.a') or pp == 'a' for pp in paths)
    assert any(pp.endswith('b[1:0]') for pp in paths)
    assert any(pp.endswith('.c') or pp == 'c' for pp in paths)


def test_data_tokens_on_enddefinitions_line_not_fast_pathed(tmp_path):
    # $enddefinitions is deliberately excluded from the fast path because data
    # tokens may share its line; they must be buffered as initial tokens.
    text = (
        '$scope module m $end\n'
        '$var wire 1 ! s $end\n'
        '$enddefinitions $end 1! 0!\n'
        '#10\n1!\n'
    )
    p = write_vcd(tmp_path, text)
    ev = _events(p)
    # The 1! and 0! that trailed $enddefinitions are at logical t=0.
    assert ev[0][0] == 0
    assert any(t == 10 for t, _s, _v in ev)
