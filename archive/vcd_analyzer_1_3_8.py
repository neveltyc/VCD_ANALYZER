#!/usr/bin/env python3
"""VCD waveform analyzer for Agent-based RTL debug.

Usage: vcd_analyzer [--json] <command> <file> [options]

Commands:
  info       <file>                               File overview (timescale, signal count, time span, scopes)
  list       <file> [--filter K1,K2]               List signals with path and bit width
  dump       <file> [--begin T] [--end T] [--filter K1,K2]   Print signal value changes in time order
  summary    <file> [--begin T] [--end T] [--filter K1,K2]   Per-signal stats: change count, unique values, static detection
  snapshot   <file> --at T [--filter K1,K2]        Known signal values at a given time point
  compare    <file> --at T1,T2 [--filter K1,K2]    Diff signal values between two time points
  search     <file> --condition C [--show K1,K2] [--changed K] [--begin T] [--end T]
                                                        Conditional search and associated signal observation

Global options:
  --json       Output compact structured JSON instead of text (time fields include *_ticks)
  --limit N    Max rows/records to emit; default 200; 0 = unlimited.
               Streaming commands stop after detecting the first unshown result.
  --verbose    Show extra fields; if --limit is omitted, disables truncation

Argument formats:
  <file>          VCD file path
  --filter K1,K2  Comma-separated patterns. Plain text uses case-insensitive substring match;
                  patterns containing * or ? use case-insensitive glob match.
                  e.g. --filter clk,rst   --filter '*_valid,*_ready,*_data'   --filter 'top.u_dma.*'
  --begin T       Start time with optional unit suffix: 0, 100ns, 17.5us, 1ms, 500ps, 200fs
  --end T         End time, same format as --begin. Omit for no upper bound
  --at T          Time point for snapshot. For compare: two points comma-separated: --at 17.5us,17.7us
  --condition C   Comma-separated AND conditions: SIG=VAL, SIG==VAL, SIG!=VAL.
                  Condition signal patterns must match exactly one signal.
                  SIG!=VAL does not match x/z/undef; use SIG=x to search unknown.
                  Values use numeric or 4-state matching: 5, 0x5, b0101, b1x0z.
  --show K1,K2    Optional associated signals to display while condition holds;
                  segment mode splits whenever shown values change.
  --changed K     Optional trigger signal; emit events only when this signal really changes.
                  For ordinary signals, first observed values are not treated as changes.
                  VCD event variables count each trigger; t=0 initialization is ignored.

Examples:
  vcd_analyzer info sim.vcd
  vcd_analyzer list sim.vcd --filter tdata,tvalid,tready
  vcd_analyzer dump sim.vcd --begin 17.5us --end 17.6us --filter clk,rst,state
  vcd_analyzer summary sim.vcd --filter dll_st,locked
  vcd_analyzer snapshot sim.vcd --at 17.55us --filter init_done,state
  vcd_analyzer compare sim.vcd --at 17.535us,17.56us --filter init_done,link_active,state
  vcd_analyzer search sim.vcd --condition "state=5"
  vcd_analyzer search sim.vcd --condition "arvalid=1,arready=1" --show araddr,arlen,arid
  vcd_analyzer search sim.vcd --changed data_out --condition "valid=0" --show data_out,valid
  vcd_analyzer search sim.vcd --condition "valid=x"
  vcd_analyzer --json summary sim.vcd --filter tvalid,tready

Notes:
  search requires at least one observed value_change in the VCD data section;
  empty waveforms are reported as an input/data issue rather than as a false
  "no match" result.
"""

__version__ = '1.3.8'

import sys
import os
import re
import math
import json
import argparse
from collections import defaultdict

# -- Time utilities ----------------------------------------------------------

_UNITS = {'fs': 1e-15, 'ps': 1e-12, 'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}


# Resource limits — generous defaults that never trip on real engineering
# files but reject pathological/malicious inputs cleanly.
# Override per-process via environment variables, e.g.:
#   VCD_ANALYZER_MAX_VARS=2000000 vcd_analyzer info big.vcd
def _env_int(name, default):
    """Read a positive integer resource limit from the environment."""
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


MAX_VARS = _env_int('VCD_ANALYZER_MAX_VARS', 1_000_000)
MAX_REASSEMBLE_BITS = _env_int('VCD_ANALYZER_MAX_REASSEMBLE_BITS', 65536)
MAX_TIME_ARG_LEN = 100         # CLI/programmatic time string length cap
MAX_TIME_TICKS = (1 << 63) - 1  # int64 max — keeps downstream arithmetic safe
MAX_FILTER_PATTERN_LEN = 256
MAX_FILTER_WILDCARDS = 16

# Additional header-section caps. Defaults are far above any legitimate
# engineering VCD but cleanly refuse pathological/malicious construction.
#
# Two failure modes are used:
#  - fail-fast (raise _VCDResourceError): for caps whose violation would
#    corrupt data correctness (lost value_changes, lost $var declarations,
#    deep scope that breaks path reconstruction).
#  - silent drop (truncate retained list): for metadata-only caps whose
#    violation only affects the cosmetic output of `info --verbose`. These
#    are noted inline where they apply.
MAX_INT_DIGITS = 100              # any int-from-string in header (width, bit idx, msb/lsb)
MAX_SIGNAL_WIDTH = MAX_REASSEMBLE_BITS  # max bits per single $var declaration
MAX_VALUE_ARG_LEN = MAX_SIGNAL_WIDTH + 2  # target value string, allows b<MAX_SIGNAL_WIDTH bits>
MAX_DECIMAL_VALUE_DIGITS = 100  # avoid Python 3.9 int() CPU DoS on --value decimal
MAX_HEX_VALUE_DIGITS = max(1, (MAX_SIGNAL_WIDTH + 3) // 4)
MAX_HEADER_BODY_TOKENS = 131072   # any $<kw>...$end section body length (metadata-only effect:
                                  # truncates $comment / $date / $version bodies; $var bodies
                                  # are never long enough to be affected in practice)
MAX_COMMENTS = 1024               # number of $comment sections retained (metadata-only)
MAX_SCOPE_DEPTH = 256             # $scope nesting depth (fail-fast: lost scope breaks path)
MAX_INITIAL_TOKENS = 131072       # tokens buffered from same line as $enddefinitions $end
                                  # (fail-fast: these are data tokens, dropping them
                                  # would silently corrupt waveforms)


# IEEE 1364-2005 18.2.2 real value_change is 'r' + real_number where
# real_number follows C99 printf("%g") shape: optional sign, integer and/or
# fractional digits, optional exponent. Used to reject garbage tokens like
# 'reset' that start with 'r' but aren't a numeric value_change.
#
# Pattern written to avoid backtracking (no alternation overlap):
#   sign?  ( digits  ( '.' digits? )?  |  '.' digits )  exponent?
# The two top-level alternatives are disjoint (start with digit vs '.'),
# so the engine never has to backtrack between them. Inputs are also
# length-bounded below; real_number tokens in VCD value_changes shouldn't
# exceed reasonable %g output width.
_REAL_RE = re.compile(
    r'^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$'
)
_REAL_MAX_LEN = 64  # Defensive cap: %.16g + sign + exponent fits well under this

# Extended VCD port state character → 4-state mapping (IEEE 1364-2005 18.4.3.1).
# Strengths (driver levels 0-7) are not exposed; for RTL debug the 4-state value
# is what matters. Conflict states (d/u/l/h) collapse to their logical level.
_PORT_STATE = {
    # Input (testfixture)
    'D': '0', 'U': '1', 'N': 'x', 'Z': 'z', 'd': '0', 'u': '1',
    # Output (DUT)
    'L': '0', 'H': '1', 'X': 'x', 'T': 'z', 'l': '0', 'h': '1',
    # Unknown direction (both input and output active)
    '0': '0', '1': '1', '?': 'x', 'F': 'z',
    'A': 'x', 'a': 'x', 'B': 'x', 'b': 'x', 'C': 'x', 'c': 'x', 'f': 'z',
}


def _parse_timescale(text):
    """Extract base time unit in seconds from $timescale line.

    IEEE 1364-2005 18.2.3.8 only allows 1, 10, or 100 as the number, but
    we accept any positive integer for lenience. A zero, missing, or
    pathologically long number falls back to 1e-12 (1 ps) — the standard's
    default — to avoid downstream division-by-zero in parse_time and CPU
    DoS from int() on huge digit strings (Python 3.9 is O(n^2)).
    """
    m = re.search(r'(\d+)\s*(fs|ps|ns|us|ms|s)', text)
    if not m:
        return 1e-12
    digits = m.group(1)
    # Length cap matches parse_time's MAX_TIME_ARG_LEN. The standard allows
    # only 1/10/100 (≤3 digits), so anything multi-line absurd is corruption.
    if len(digits) > MAX_TIME_ARG_LEN:
        return 1e-12
    n = int(digits)
    if n <= 0:
        return 1e-12
    return n * _UNITS[m.group(2)]


class _TimeParseError(ValueError):
    """Raised by parse_time on invalid input; caught in main() for friendly CLI errors."""


class _FilterParseError(argparse.ArgumentTypeError):
    """Raised when --filter contains an unsafe or unsupported pattern.
    argparse handles this automatically with a friendly message."""


class _ValueParseError(ValueError):
    """Raised when a target value is too large or malformed beyond tolerant matching."""


class _ConditionParseError(ValueError):
    """Raised when search --condition / --show / --changed is invalid."""


class _VCDResourceError(RuntimeError):
    """Raised when a VCD input exceeds configured resource limits.
    Surfaced in main() as a CLI error, no Python traceback."""


def _check_time_range(ticks, original):
    if ticks < 0:
        raise _TimeParseError('time must be non-negative; got {!r}'.format(original))
    if ticks > MAX_TIME_TICKS:
        raise _TimeParseError(
            'time value too large; got {!r}, max ticks is {}'.format(original, MAX_TIME_TICKS))
    return ticks


def _parse_vcd_timestamp_token(tok):
    """Parse a VCD '#<digits>' simulation_time token into an int.

    Returns int on success, None for malformed input (e.g. '#1.5' — digit
    prefix passed the isdigit() pre-check but int() rejects it). The
    None-path preserves the round-7 "tolerant reader" behavior: malformed
    timestamps are silently skipped, the rest of the stream continues.

    Raises _VCDResourceError for inputs that would cause CPU/memory DoS or
    exceed int64. Python 3.11+ has PEP 678 (int_max_str_digits) baked in,
    but we target 3.9 where int(s) is O(n^2) for huge n; even on 3.11+
    the PEP 678 ValueError would otherwise become an unhandled traceback.
    """
    digits = tok[1:]
    if len(digits) > MAX_TIME_ARG_LEN:
        raise _VCDResourceError(
            'VCD timestamp token too long: {} digits (max {}); '
            'file may be corrupt or malicious'.format(len(digits), MAX_TIME_ARG_LEN))
    try:
        v = int(digits)
    except ValueError:
        return None  # tolerated malformed (e.g. '#1.5')
    if v > MAX_TIME_TICKS:
        raise _VCDResourceError(
            'VCD timestamp too large: got {}, max ticks is {}'.format(v, MAX_TIME_TICKS))
    return v


def _safe_int_digits(s):
    """Parse a digit string from VCD header to int with bounded cost.

    Used wherever the header declares an integer in user-controlled
    position: $var width, [msb:lsb] range, [N] bit index. Returns int
    on success, None for empty / malformed / oversized inputs. Never
    raises — caller decides whether to skip the declaration or raise
    _VCDResourceError with richer context.

    Length cap MAX_INT_DIGITS=100 defends against the same Python 3.9
    O(n^2) decimal-int and Python 3.11+ PEP 678 ValueError issues as
    _parse_vcd_timestamp_token. 100 digits is far beyond any legitimate
    bit width or index (which fit in 4 digits comfortably).
    """
    if not s or len(s) > MAX_INT_DIGITS:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def parse_time(s, ts_sec):
    """Parse time string with optional unit suffix to internal VCD timestamp.

    VCD timestamps per IEEE 1364-2005 18.2.3.8 are non-negative integers.
    - With unit: any non-negative value, scaled to ticks (e.g. '17.5us', '.5ns')
    - Without unit: must be a non-negative integer tick count

    Bare '10.5' (no unit) is rejected to avoid silent int() truncation;
    use '10.5ns' to specify a fractional time. Whitespace between number
    and unit is NOT allowed ('5 ns' is rejected; standard unit literals
    are written as a single token).

    Hardened against:
    - ZeroDivisionError when ts_sec <= 0 (e.g. malformed $timescale)
    - Overflow / non-finite intermediate values
    - Overlong input strings (CPU DoS)
    - Tick counts exceeding int64
    """
    if s is None:
        return None
    if not isinstance(s, str):
        raise _TimeParseError(
            'time value must be a string; got {}'.format(type(s).__name__))
    if len(s) > MAX_TIME_ARG_LEN:
        raise _TimeParseError(
            'time value too long; max length is {}'.format(MAX_TIME_ARG_LEN))
    stripped = s.strip()
    # Anchored match — no \s* between value and unit ('5 ns' must be rejected).
    m = re.match(r'^([+-]?)(\d+\.\d*|\.\d+|\d+)(fs|ps|ns|us|ms|s)?$', stripped)
    if not m:
        # Fall back to bare integer ('100', '-5'); reject anything else.
        try:
            v = int(stripped)
        except (ValueError, TypeError):
            raise _TimeParseError(
                'invalid time value {!r}; expected integer ticks or value '
                'with fs/ps/ns/us/ms/s suffix'.format(s))
        return _check_time_range(v, s)
    sign, val_str, unit = m.group(1), m.group(2), m.group(3)
    if sign == '-' and val_str.strip('0.') != '':
        # Reject negative non-zero. '-0' / '-0.0' silently treated as 0.
        raise _TimeParseError(
            'time must be non-negative; got {!r}'.format(s))
    if unit is None:
        if '.' in val_str:
            raise _TimeParseError(
                'bare numeric time must be integer ticks; got {!r}. '
                'Use a unit suffix for fractional times, e.g. {}ns'.format(s, val_str))
        return _check_time_range(int(val_str), s)
    if ts_sec <= 0:
        raise _TimeParseError(
            'cannot convert time with unit because VCD $timescale is 0 or invalid')
    try:
        scaled = float(val_str) * _UNITS[unit] / ts_sec
    except (OverflowError, ValueError, ZeroDivisionError):
        raise _TimeParseError('invalid time value {!r}'.format(s))
    if not math.isfinite(scaled):
        raise _TimeParseError('time value {!r} is not finite'.format(s))
    return _check_time_range(int(round(scaled)), s)


def fmt_time(ts, ts_sec):
    """Format internal timestamp to human-readable string.

    Picks the smallest unit u where |scaled| < 1000, preferring natural
    boundaries. E.g. with timescale 1ns, #5 prints as '5ns' not '5000ps';
    #17534700 prints as '17.5347us'.

    Defensive: non-finite ts or ts_sec produces '?', not 'infs' / 'nans'.
    """
    if ts == 0:
        return '0s'
    # math.isfinite handles int, float, bool. inf/nan slip through arithmetic
    # otherwise and produce garbage like 'infs'.
    try:
        if not (math.isfinite(ts) and math.isfinite(ts_sec)):
            return '?'
    except TypeError:
        return '?'
    if ts_sec <= 0:
        return '?'
    sec = ts * ts_sec
    for u in ('fs', 'ps', 'ns', 'us', 'ms', 's'):
        scaled = sec / _UNITS[u]
        if abs(scaled) < 1000 or u == 's':
            return '{:g}{}'.format(scaled, u)
    return '{:g}s'.format(sec)


# -- Value formatting --------------------------------------------------------

def fmt_val(value, info):
    """Format signal value per IEEE 1364-2005 18.2.2.

    info: dict with 'width' (required) and 'type' (optional, default 'wire').

    Real/realtime values (18.2.2) carry the simulator's %.16g rendering as
    their literal value string and have no bit width — declared width (often
    64) is purely cosmetic and must not trigger vector left-extension.
    Multi-bit vectors are left-extended per Table 18-1: MSB X/Z extends
    with X/Z, else 0. Events (var_type 'event' per 18.2.3.7) display as
    'triggered' since the dumped value is just a marker.
    """
    vtype = info.get('type', 'wire')
    if vtype == 'event':
        return 'triggered'
    if vtype in ('real', 'realtime'):
        return value
    width = info['width']
    # Malformed VCD may dump more 4-state bits than the declared width
    # (for example an over-long extended-VCD port state). Do not truncate
    # to the LSBs: that silently fabricates a plausible numeric value.
    # Show explicit unknowns instead.
    if _is_4state_bits(value) and len(value) > width:
        value = 'x' * width
    if width == 1:
        return value
    # Left-extend short vectors. Writer drops redundant MSB bits when they
    # match the extension char of MSB (Table 18-2).
    if len(value) < width:
        msb = value[0]
        pad = msb if msb in ('x', 'z') else '0'
        value = pad * (width - len(value)) + value
    if 'x' in value or 'z' in value:
        return 'b' + value
    try:
        d = int(value, 2)
        hw = max((width + 3) // 4, 1)
        return '{} (0x{})'.format(d, format(d, 'x').zfill(hw))
    except ValueError:
        return 'b' + value


def val_to_int(value):
    """Try converting to int, None on x/z or pathologically long values.

    int(s, 2) is O(n) for base-2 (PEP 678 does not apply to power-of-two
    bases) so the worst case after MAX_SIGNAL_WIDTH=65536 is sub-ms — but
    we cap anyway as defense in depth, in case a future code path lets
    an unbounded value reach here.
    """
    if 'x' in value or 'z' in value:
        return None
    if len(value) > MAX_SIGNAL_WIDTH:
        return None
    try:
        return int(value, 2) if len(value) > 1 else int(value)
    except ValueError:
        return None




def _clamp_overwide_logic_value(value, info):
    """Preserve clean 4-state state while rejecting malformed over-wide dumps.

    Legal VCD writers may omit redundant MSB bits; fmt_val() and condition
    matching already left-extend short values. A value longer than the
    declared width is malformed. Do not truncate it to the LSBs: that would
    turn corrupt input into a plausible-looking numeric value. Instead,
    degrade to all-x at the declared width so downstream dump/snapshot/search
    sees an explicit unknown.
    """
    vtype = info.get('type', 'wire')
    if vtype in ('real', 'realtime', 'event'):
        return value
    width = info.get('width')
    if width is None:
        return value
    if _is_4state_bits(value) and len(value) > width:
        return 'x' * width
    return value

def _normalize_filter_patterns(value):
    """Normalize and bound user-supplied substring/glob patterns.

    Plain text remains substring matching. Only '*' and '?' trigger glob
    matching; '[' is literal because VCD bus ranges like data[7:0] are
    common signal names. Pattern length and wildcard count are bounded
    to keep Python 3.9's fnmatch/regex translation from becoming a CPU
    DoS surface ('a*a*a*...b' style inputs can be slow in older Python).
    Consecutive '*' are collapsed (matches glob semantics, reduces backtracking).

    Used by:
    - argparse type= on --filter (raises argparse-friendly error)
    - VCDParser.match() applied to internally-stored keyword lists
    """
    if value is None:
        return None
    if isinstance(value, str):
        raw_patterns = value.split(',')
    elif isinstance(value, (list, tuple, set)):
        raw_patterns = value
    else:
        raise _FilterParseError(
            'filter patterns must be a string or a sequence of strings; got {}'.format(
                type(value).__name__))
    out = []
    for raw in raw_patterns:
        pat = str(raw).strip()
        if not pat:
            continue
        if len(pat) > MAX_FILTER_PATTERN_LEN:
            raise _FilterParseError(
                'filter pattern too long; max length is {}'.format(MAX_FILTER_PATTERN_LEN))
        pat = re.sub(r'\*+', '*', pat)  # collapse `**` → `*`
        if pat.count('*') + pat.count('?') > MAX_FILTER_WILDCARDS:
            raise _FilterParseError(
                'too many wildcard characters in filter pattern; max is {}'.format(
                    MAX_FILTER_WILDCARDS))
        out.append(pat)
    return out


def _glob_lite_regex(pattern):
    """Translate the tool's minimal glob syntax to a compiled regex.

    Only '*' and '?' are special. Everything else — notably '[' and ']' in
    VCD bus ranges such as data[7:0] — is matched literally. This deliberately
    avoids fnmatch's character-class syntax so documented filters like
    '*data[7:0]' match the literal signal path 'tb.data[7:0]'.

    Pattern length and wildcard count are already bounded by
    _normalize_filter_patterns(), so the generated regex is small and safe.
    """
    parts = ['^']
    for ch in pattern:
        if ch == '*':
            parts.append('.*')
        elif ch == '?':
            parts.append('.')
        else:
            parts.append(re.escape(ch))
    parts.append('$')
    return re.compile(''.join(parts))


# -- VCD Parser with bit-exploded signal reassembly -------------------------

# IEEE 1364-2005 declaration keywords that introduce a $<kw> ... $end section.
_DECL_KEYWORDS = {'$timescale', '$scope', '$upscope', '$var',
                  '$comment', '$date', '$version', '$enddefinitions'}

# Simulation keywords that wrap value_changes until $end. The keyword and $end
# are pure markers — the wrapped value_changes are parsed normally.
# Four-state VCD (18.2.3.9-12) + extended VCD (18.4.1 BNF).
_SIM_KEYWORDS = {'$dumpall', '$dumpoff', '$dumpon', '$dumpvars',
                 '$dumpports', '$dumpportsoff', '$dumpportson', '$dumpportsall'}

# Sections that can appear in the data area whose body is NOT value_changes
# and must be skipped wholesale until $end. $comment (18.2.3.1) is in both
# header and data; $vcdclose (18.3.6.1) wraps a final simulation time token.
_DATA_SKIP_SECTIONS = {'$comment', '$vcdclose'}


class VCDParser:
    """Streaming VCD parser. Token-based: handles single-line and multi-line
    sections, inline simulation keyword blocks, and multi-line port values
    per IEEE 1364-2005 Section 18.

    Auto-reassembles bit-exploded signals (QuestaSim writes 512-bit signals
    as 512 individual 1-bit $var entries with [N] suffix).

    Extended VCD ($dumpports) support level: port_state characters are
    lowered to 4-state values (0/1/x/z) for RTL debug. The strength0 and
    strength1 components are parsed but discarded — preserving them would
    rarely benefit RTL-level analysis and clutters the value display.
    """

    def __init__(self, path):
        self.path = path
        self.ts_str = ''
        self.ts_sec = 1e-12        # timescale in seconds
        self.signals = {}           # sig_id -> {path, width, type, aliases}
        self._data_offset = 0
        # Header metadata per IEEE 1364-2005 18.2.3:
        #   $date    - simulation date string (18.2.3.2)
        #   $version - simulator vendor/version (18.2.3.3)
        #   $comment - free-form, may appear multiple times (18.2.3.1)
        # Captured verbatim for provenance display; an agent inspecting an
        # unknown VCD benefits from knowing which simulator produced it
        # (QuestaSim 2023.1 vs Icarus Verilog vs VCS) and when, since
        # downstream debug heuristics may depend on simulator quirks.
        self.date = ''
        self.version = ''
        self.comments = []
        # If $enddefinitions $end is followed by data tokens on the same
        # line(s) buffered by readline, those tokens replay first in data.
        self._initial_tokens = []
        self._bit_map = {}          # sym -> (sig_id, bit_index)
        self._bit_state_template = {}  # sig_id -> initial bit list for replay-local reassembly
        self._parse_header()

    def _parse_header(self):
        """Token-based header parse. Sections may span multiple lines;
        $end is the only terminator (IEEE 1364-2005 18.2.1)."""
        scope = []
        raw_vars = []  # (sym, name, width, bit_idx_str, scope_path, vtype)
        current_kw = None
        body = []
        done = False

        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            while not done:
                line = f.readline()
                if not line:
                    break
                for tok in line.split():
                    if done:
                        # Buffer tokens that share the same line as
                        # `$enddefinitions $end`. These are data tokens
                        # (value_changes, timestamps), so they MUST NOT
                        # be silently dropped — that would corrupt the
                        # waveform without the user noticing. Fail-fast.
                        # Normal VCDs have at most a handful of tokens
                        # on this line; 131072 is comfortably above any
                        # legitimate use.
                        if len(self._initial_tokens) >= MAX_INITIAL_TOKENS:
                            raise _VCDResourceError(
                                'too many data tokens on the same line as '
                                '$enddefinitions $end (>{}); file may be '
                                'corrupt or malicious'.format(MAX_INITIAL_TOKENS))
                        self._initial_tokens.append(tok)
                        continue
                    if current_kw is None:
                        if tok in _DECL_KEYWORDS:
                            current_kw = tok
                            body = []
                        # else: stray token, ignore
                    elif tok == '$end':
                        # Section complete
                        if current_kw == '$timescale':
                            ts_body = ' '.join(body)
                            self.ts_str = '$timescale ' + ts_body + ' $end'
                            self.ts_sec = _parse_timescale(ts_body)
                        elif current_kw == '$scope' and len(body) >= 2:
                            # Cap nesting depth to defend against
                            # 1M-level $scope-without-$upscope construction.
                            if len(scope) >= MAX_SCOPE_DEPTH:
                                raise _VCDResourceError(
                                    '$scope nesting depth exceeds {}; '
                                    'file may be corrupt or malicious'.format(MAX_SCOPE_DEPTH))
                            scope.append(body[1])
                        elif current_kw == '$upscope':
                            if scope:
                                scope.pop()
                        elif current_kw == '$var' and len(body) >= 4:
                            vtype = body[0]

                            def _collect_bracket(tokens, i):
                                if i >= len(tokens) or not tokens[i].startswith('['):
                                    return None, i
                                parts = []
                                while i < len(tokens):
                                    parts.append(tokens[i])
                                    if ']' in tokens[i]:
                                        return ''.join(parts), i + 1
                                    i += 1
                                return None, i

                            size_expr, idx_after_size = _collect_bracket(body, 1)
                            if size_expr is not None:
                                m = re.match(r'\[(\d+):(\d+)\]$', size_expr)
                                if not m:
                                    current_kw = None
                                    continue
                                msb = _safe_int_digits(m.group(1))
                                lsb = _safe_int_digits(m.group(2))
                                if msb is None or lsb is None:
                                    # Overlong or malformed digits — skip
                                    # this $var rather than abort, since
                                    # the rest of the header may still be
                                    # useful.
                                    current_kw = None
                                    continue
                                w = abs(msb - lsb) + 1
                                idx = idx_after_size
                            else:
                                w = _safe_int_digits(body[1])
                                if w is None:
                                    current_kw = None
                                    continue
                                idx = 2
                            # Hazard 1 mitigation: refuse pathological widths
                            # before they reach fmt_val (which would try to
                            # allocate `pad * (width - len(value))` bytes).
                            # Real signals never approach MAX_SIGNAL_WIDTH.
                            if w <= 0 or w > MAX_SIGNAL_WIDTH:
                                raise _VCDResourceError(
                                    '$var width {} exceeds max {}; '
                                    'file may be corrupt or malicious'.format(
                                        w, MAX_SIGNAL_WIDTH))
                            if len(body) <= idx + 1:
                                current_kw = None
                                continue
                            sym, name = body[idx], body[idx + 1]

                            # Per IEEE 1364 free-format, the bracket reference
                            # range can be split into several tokens, e.g.
                            # 'data [7 : 0]' → ['data', '[7', ':', '0]'].
                            bit_str, _idx_after_ref = _collect_bracket(body, idx + 2)
                            # Per IEEE 1364-2005 18.2.3.7 reference syntax:
                            #   identifier [bit_select_index]      → single bit
                            #   identifier [msb_index : lsb_index] → range
                            # For multi-bit refs with a range, fold it into
                            # the name so the displayed path is 'data[7:0]'.
                            # For w==1 with [N], keep bit_str separate for
                            # the bit-explosion heuristic below.
                            if bit_str is not None and w > 1:
                                name = name + bit_str
                                bit_str = None
                            # Resource cap: refuse to allocate unbounded memory
                            # for malicious VCDs declaring millions of $var.
                            # Default 500k is ~25x larger than typical QuestaSim
                            # files; tune via VCD_ANALYZER_MAX_VARS env var.
                            if len(raw_vars) >= MAX_VARS:
                                raise _VCDResourceError(
                                    'too many $var declarations: more than {}. '
                                    'Set VCD_ANALYZER_MAX_VARS to raise the limit.'.format(MAX_VARS))
                            raw_vars.append((sym, name, w, bit_str, '.'.join(scope), vtype))
                        elif current_kw == '$enddefinitions':
                            done = True
                        elif current_kw == '$date':
                            # Tokens collapsed to single-spaced string;
                            # original used \t / multi-line for readability.
                            self.date = ' '.join(body)
                        elif current_kw == '$version':
                            self.version = ' '.join(body)
                        elif current_kw == '$comment':
                            # Per 18.2.3.1, $comment may appear multiple
                            # times. Silent drop after the cap is safe:
                            # comments are metadata, not data — losing
                            # the 1025th comment only affects what
                            # `info --verbose` prints, never the waveform.
                            if len(self.comments) < MAX_COMMENTS:
                                self.comments.append(' '.join(body))
                        current_kw = None
                    else:
                        # Bound section body. In practice this only
                        # truncates oversized $comment / $date / $version
                        # bodies — metadata. $var bodies are 4-8 tokens,
                        # $scope is 2, $timescale is 2; none come close
                        # to the cap. Silent drop is safe because:
                        #   - the $end token still closes the section
                        #     correctly (we still see it in the outer
                        #     loop, we just stop appending to body)
                        #   - dropped tokens never become part of any
                        #     value_change interpretation
                        if len(body) < MAX_HEADER_BODY_TOKENS:
                            body.append(tok)
            self._data_offset = f.tell()

        # Phase 2: detect and reassemble bit-exploded signals.
        # Bit-exploded heuristic per QuestaSim convention: each bit is a
        # 1-bit $var with [N] suffix. We auto-reassemble ONLY when the bit
        # indices form a complete 0..max_bit contiguous set. Standard-legal
        # partial dumps (e.g. only $var ... bus[4] ... emitted) must NOT be
        # synthesized as a bus[4:0] with phantom lower bits — they are kept
        # as individual bit-select references.
        bit_groups = defaultdict(dict)  # (scope, base_name) -> {bit_idx: sym}
        bit_types = {}                   # (scope, base_name) -> vtype
        duplicate_bit_groups = set()      # groups with duplicate bit indices; never reassemble
        standalone = []
        bit_select_singletons = []       # (sym, name, idx, sc, vtype)

        for sym, name, w, bit_str, sc, vtype in raw_vars:
            if w == 1 and bit_str is not None:
                m = re.match(r'\[(\d+)\]', bit_str)
                if m:
                    idx = _safe_int_digits(m.group(1))
                    if idx is None:
                        # Overlong/malformed bit index — treat the $var as
                        # a standalone signal (its bit_str folded back).
                        standalone.append((sym, name + bit_str, 1, sc, vtype))
                        continue
                    group_key = (sc, name)
                    group = bit_groups[group_key]
                    if idx in group:
                        # Illegal VCD: duplicate bit-select declaration for the
                        # same reconstructed bus bit.  Do not silently let the
                        # later symbol overwrite the earlier one; mark the group
                        # non-reassemblable so all raw bit-select declarations
                        # remain visible as standalone signals.
                        duplicate_bit_groups.add(group_key)
                    else:
                        group[idx] = sym
                    # Resource cap: refuse to allocate gigantic synthesized
                    # buses (per-call template copy cost scales linearly).
                    # Default 65536 is 128× typical QuestaSim bit-bus size;
                    # tune via VCD_ANALYZER_MAX_REASSEMBLE_BITS env var.
                    if len(group) > MAX_REASSEMBLE_BITS:
                        raise _VCDResourceError(
                            'bit-exploded group {}.{} has more than {} bits. '
                            'Set VCD_ANALYZER_MAX_REASSEMBLE_BITS to raise the limit.'.format(
                                sc or '<root>', name, MAX_REASSEMBLE_BITS))
                    bit_types[(sc, name)] = vtype
                    bit_select_singletons.append((sym, name, idx, sc, vtype))
                    continue
                # A 1-bit reference written as a range (for example
                # data[0:0]) is not a bit-exploded bus bit. Preserve the
                # reference suffix in the displayed path instead of silently
                # dropping it. Some simulators emit this non-canonical form.
                standalone.append((sym, name + bit_str, 1, sc, vtype))
                continue
            standalone.append((sym, name, w, sc, vtype))

        # Partition bit_groups: contiguous-from-0 with ≥2 bits → reassemble;
        # everything else → individual bit-select references. A single
        # '[0]' declaration alone is NOT a bus — it's a partial dump that
        # happens to use bit 0; synthesizing it as 'data[0:0]' would lie
        # about the file structure.
        #
        # DoS guard: do NOT compute set(range(max+1)) — a malicious VCD with
        # 'bus[0]' + 'bus[1000000000]' would force materialization of a
        # billion-element set (gigabytes of RAM). Indices [0..max] form a
        # contiguous run iff: count == max+1 AND 0 is present. Both checks
        # are O(1) on dict_keys.
        non_contiguous = set(duplicate_bit_groups)
        for key, bits in bit_groups.items():
            if key in non_contiguous:
                continue
            indices = bits.keys()
            n = len(indices)
            if n < 2:
                non_contiguous.add(key)
                continue
            max_idx = max(indices)
            if max_idx + 1 != n or 0 not in indices:
                non_contiguous.add(key)

        # Each non-contiguous bit-select becomes a standalone 'name[idx]' signal
        for sym, name, idx, sc, vtype in bit_select_singletons:
            if (sc, name) in non_contiguous:
                standalone.append((sym, '{}[{}]'.format(name, idx), 1, sc, vtype))

        # Register standalone signals. Per IEEE 1364-2005 18.2.3.7, the same
        # identifier_code can be referenced under multiple paths. First seen
        # type wins when aliases have different var_types.
        for sym, name, w, sc, vtype in standalone:
            path = '{}.{}'.format(sc, name) if sc else name
            if sym in self.signals:
                self.signals[sym]['aliases'].append(path)
                if sc and sc not in self.signals[sym].setdefault('scopes', []):
                    self.signals[sym]['scopes'].append(sc)
            else:
                self.signals[sym] = {
                    'path': path, 'width': w, 'type': vtype,
                    'aliases': [path], 'scope': sc, 'scopes': [sc] if sc else []
                }

        for (sc, name), bits in bit_groups.items():
            if not bits or (sc, name) in non_contiguous:
                continue
            max_bit = max(bits.keys())
            width = max_bit + 1
            path = '{}.{}[{}:0]'.format(sc, name, max_bit) if sc else '{}[{}:0]'.format(name, max_bit)
            sig_id = '__grp__{}__{}'.format(sc, name)
            self.signals[sig_id] = {
                'path': path, 'width': width,
                'type': bit_types.get((sc, name), 'wire'),
                'aliases': [path], 'scope': sc, 'scopes': [sc] if sc else [],
                'synthesized': True,    # bit-exploded reassembled bus
                'raw_bits': len(bits),  # number of $var declarations consumed
            }
            self._bit_state_template[sig_id] = ['x'] * width
            # Per IEEE 1364-2005 18.2.3.7, the same identifier_code can be
            # referenced under multiple paths. When two bit-exploded buses
            # share per-bit identifier codes (e.g. bus[0]/aliasbus[0] both
            # use '!'), each is a separate synthesized signal that must
            # update independently. _bit_map is therefore 1-to-many.
            for idx, sym in bits.items():
                self._bit_map.setdefault(sym, []).append((sig_id, idx))

        # Raw $var counts (transparent to IEEE 1364 spec) so 'info' can
        # report accurate metadata even when reassembly collapses many
        # declarations into a single synthesized bus. Distinct from
        # `signal_count` (post-reassembly view used by agent commands).
        self.raw_var_count = len(raw_vars)
        self.raw_type_counts = defaultdict(int)
        for _sym, _name, _w, _bit_str, _sc, vtype in raw_vars:
            self.raw_type_counts[vtype] += 1

    def match(self, keywords):
        """Return set of sig_ids matching any pattern, or None for all.

        Plain patterns use case-insensitive substring matching. Patterns
        containing '*' or '?' use the tool's minimal glob-lite matching:
        '*' matches any span, '?' matches one character, and all other
        characters are literal. This intentionally differs from fnmatch:
        '[' and ']' are NOT character-class delimiters because VCD bus ranges
        like data[7:0] are common signal names.

        Input is normalized through _normalize_filter_patterns to bound
        pattern length and wildcard count.
        """
        if not keywords:
            return None
        raw_pats = [k.lower() for k in _normalize_filter_patterns(keywords) or []]
        if not raw_pats:
            return None
        pats = []
        for pat in raw_pats:
            if any(ch in pat for ch in '*?'):
                pats.append(('glob', _glob_lite_regex(pat)))
            else:
                pats.append(('substr', pat))
        out = set()
        for sid, info in self.signals.items():
            for path in info['aliases']:
                pl = path.lower()
                hit = False
                for kind, pat in pats:
                    hit = pat.match(pl) is not None if kind == 'glob' else pat in pl
                    if hit:
                        out.add(sid)
                        break
                if hit:
                    break
        return out

    def _data_tokens(self):
        """Generator yielding all tokens from the data section."""
        for t in self._initial_tokens:
            yield t
        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(self._data_offset)
            for line in f:
                for t in line.split():
                    yield t

    def iter_events(self, t0=0, t1=None, sids=None):
        """Yield (time, sig_id, value_str) with bit reassembly.

        Token-based, context-sensitive. Section keywords ($comment/$vcdclose/
        $dumpvars/$dumpoff/$dumpon/$dumpall/$dumpports*) are only recognized
        when the parser is at a top-level position (expecting either a
        timestamp or a value_change opener). After 'b<bits>', 'r<num>', or
        'p<state> <s0> <s1>' the NEXT token is consumed as identifier_code
        even if it happens to be the string '$comment' (legal per
        IEEE 1364-2005 18.2.1: identifier_code is any printable ASCII).

        Initial value changes appearing before any '#T' timestamp are
        emitted at logical t=0 (typical case: $dumpvars block directly
        after $enddefinitions without a leading #0).
        """
        cur_t = 0
        pending = {}

        def _flush():
            if not pending:
                return []
            items = list(pending.items())
            pending.clear()
            return items

        # Pushback-capable token stream. Lets us peek the next token in
        # b/r value_change branches and refuse it if it looks structural
        # (timestamp or section keyword) — otherwise malformed inputs
        # like 'b1010\n#10\n1!' would silently consume #10 as the
        # identifier_code and corrupt the timeline.
        raw = self._data_tokens()
        pushback = []
        # Replay-local bit state. iter_events() must be pure with respect
        # to parser metadata: compare/search/summary/snapshot may replay
        # the same VCDParser multiple times and in non-monotonic order.
        # Object-level mutable state would leak future bit values into
        # earlier snapshots for bit-exploded buses.
        #
        # Laziness: when the caller selected a subset of signals (sids),
        # maintain only the synthesized bit-buses that can be emitted for
        # this query. This avoids touching large unrelated bit-exploded
        # buses during catch-up scans, while preserving exact behavior for
        # selected buses and for no-filter calls.
        if sids is None:
            bit_map = self._bit_map
            bit_state = {gid: bits[:] for gid, bits in self._bit_state_template.items()}
        else:
            bit_map = {}
            needed_gids = set()
            for sym0, refs in self._bit_map.items():
                kept = [(gid, idx) for gid, idx in refs if gid in sids]
                if kept:
                    bit_map[sym0] = kept
                    for gid, _idx in kept:
                        needed_gids.add(gid)
            bit_state = {gid: self._bit_state_template[gid][:] for gid in needed_gids}

        def _next():
            return pushback.pop() if pushback else next(raw, None)

        def _looks_structural(t):
            """True only if t is a timestamp (#<digit>...) AND not a
            declared identifier_code. Per IEEE 1364-2005 18.2.1,
            identifier_code is any printable ASCII string, so '#1' can be
            both a legal symbol and (in another position) a timestamp.
            Disambiguate by checking the declared identifier table — if
            the file declared a $var with this identifier, it IS the
            symbol; otherwise treat as a stray timestamp from malformed
            input and push it back."""
            if t is None:
                return True
            if t.startswith('#') and len(t) > 1 and t[1].isdigit():
                return t not in self.signals and t not in self._bit_map
            return False

        try:
            while True:
                tok = _next()
                if tok is None:
                    break
                # Top-level: any unknown $keyword starts a section ending at
                # $end. This is safer than passing the body through as value
                # changes — '$bogus 1! $end' must not pollute the waveform.
                # Known wrappers ($dumpvars etc) are pass-through (their body
                # IS value_changes per 18.2.3.9-12).
                if tok == '$end':
                    continue
                if tok in _SIM_KEYWORDS:
                    continue
                if tok.startswith('$'):
                    # $comment, $vcdclose, $bogus, ...: drop body to $end
                    for t in raw:
                        if t == '$end':
                            break
                    continue
    
                if tok.startswith('#') and len(tok) > 1 and tok[1].isdigit():
                    new_t = _parse_vcd_timestamp_token(tok)
                    if new_t is None:
                        # Malformed (e.g. '#1.5'); silently skip per round-7 policy.
                        continue
                    if cur_t >= t0:
                        for sid, val in _flush():
                            yield cur_t, sid, val
                    cur_t = new_t
                    if t1 is not None and cur_t > t1:
                        return
                    continue
    
                # Parse one value_change. May consume 1, 2, or 4 tokens.
                # Each branch validates body shape AND that the consumed sym
                # is not actually a structural token; malformed inputs are
                # skipped without corrupting downstream parsing state.
                first = tok[0]
                if first in '01xXzZ':
                    val = first.lower()
                    sym = tok[1:]
                    if not sym:
                        continue
                elif first in 'bB':
                    bits = tok[1:]
                    if not bits or any(c not in '01xXzZ' for c in bits):
                        continue  # malformed body; do NOT consume next token
                    sym = _next()
                    if _looks_structural(sym):
                        if sym is not None:
                            pushback.append(sym)
                        continue
                    val = bits.lower()
                elif first in 'rR':
                    body = tok[1:]
                    # Length cap defends against malicious VCDs that try to
                    # exploit regex worst-case behavior with multi-KB tokens.
                    # Legitimate %.16g output is ~25 chars max.
                    if len(body) > _REAL_MAX_LEN or not _REAL_RE.match(body):
                        continue  # 'reset', 'rXYZ' etc — not a real value
                    sym = _next()
                    if _looks_structural(sym):
                        if sym is not None:
                            pushback.append(sym)
                        continue
                    val = body
                elif first == 'p':
                    # Extended VCD (18.4.3.1): p<state> <s0> <s1> <id>
                    # Strength components are single digits 0-7. Validate
                    # before consuming further tokens so a malformed
                    # 'pH #10 1!' doesn't swallow the #10 timestamp.
                    state = tok[1:] if len(tok) > 1 else ''
                    # Port state is one or more Extended VCD state characters.
                    # Reject empty/unknown state strings instead of inventing an
                    # x event from malformed input such as plain 'p 0 6 !'.
                    if not state or any(c not in _PORT_STATE for c in state):
                        continue
                    _s0 = _next()
                    if _s0 is None or len(_s0) != 1 or _s0 not in '01234567':
                        if _s0 is not None:
                            pushback.append(_s0)
                        continue
                    _s1 = _next()
                    if _s1 is None or len(_s1) != 1 or _s1 not in '01234567':
                        if _s1 is not None:
                            pushback.append(_s1)
                        pushback.append(_s0)
                        continue
                    sym = _next()
                    if _looks_structural(sym):
                        if sym is not None:
                            pushback.append(sym)
                        pushback.append(_s1)
                        pushback.append(_s0)
                        continue
                    val = ''.join(_PORT_STATE[c] for c in state)
                else:
                    continue  # unparseable token
    
                # Catch-up before t0: update bit_state only, don't emit.
                # Standalone state is owned by callers (e.g. _build_snapshot
                # accumulates it from yielded events), so nothing to do here
                # for the standalone case — the continue is correct.
                if cur_t < t0:
                    if sym in bit_map:
                        bit_val = val if _is_4state_bits(val) and len(val) == 1 else 'x'
                        for gid, idx in bit_map[sym]:
                            bit_state[gid][idx] = bit_val
                    continue
    
                # Bit-exploded signal: aggregate into virtual bus value(s).
                # If the same identifier_code drives multiple synthesized buses
                # (via aliased parent declarations), each gets its own event.
                #
                # IMPORTANT: do NOT continue after this branch. Per IEEE 1364-2005
                # 18.2.3.7, the same identifier_code can be referenced by both a
                # standalone $var (e.g. clk) AND a bit-select $var (e.g.
                # data_bus[0]) when RTL assigns one to the other. If we continued,
                # the standalone alias would silently never emit events and the
                # agent would see clk as a flat line. Fall through to the
                # standalone block so both signals update on the same value_change.
                if sym in bit_map:
                    bit_val = val if _is_4state_bits(val) and len(val) == 1 else 'x'
                    for gid, idx in bit_map[sym]:
                        bit_state[gid][idx] = bit_val
                        if sids is None or gid in sids:
                            pending[gid] = ''.join(reversed(bit_state[gid]))
    
                # Standalone signal (may run after the bit-bus branch above when
                # the sym serves both roles).
                if sym not in self.signals:
                    continue
                if sids is not None and sym not in sids:
                    continue
                pending[sym] = _clamp_overwide_logic_value(val, self.signals[sym])
    
            # Final flush
            if cur_t >= t0:
                for sid, val in _flush():
                    yield cur_t, sid, val
        finally:
            close = getattr(raw, 'close', None)
            if close is not None:
                close()

    def scan_time_range(self):
        """Min/max timestamps in the file.

        If any value_change occurs before the first #T (an initial $dumpvars
        block), t_min is 0. Time is observed-max (never less than the largest
        seen), so malformed VCDs with timestamps going backwards do not produce
        negative duration. Value-change body validation mirrors iter_events()
        closely enough that info/dump agree on malformed b/r/p bodies.

        The underlying token generator owns an open file. Close it explicitly
        on all paths instead of relying on garbage collection if a resource
        error is raised while scanning a corrupt file.
        """
        t_min = t_max = None
        saw_initial_data = False
        raw = self._data_tokens()
        pushback = []

        def _next():
            return pushback.pop() if pushback else next(raw, None)

        def _is_struct(t):
            if t is None:
                return True
            if t.startswith('#') and len(t) > 1 and t[1].isdigit():
                # Declared identifier_code with #-form is not a timestamp.
                return t not in self.signals and t not in self._bit_map
            return False

        try:
            while True:
                tok = _next()
                if tok is None:
                    break
                if tok == '$end' or tok in _SIM_KEYWORDS:
                    continue
                if tok.startswith('$'):
                    for t in raw:
                        if t == '$end':
                            break
                    continue
                if tok.startswith('#') and len(tok) > 1 and tok[1].isdigit():
                    t = _parse_vcd_timestamp_token(tok)
                    if t is None:
                        continue
                    if t_min is None:
                        t_min = 0 if saw_initial_data else t
                    t_max = t if t_max is None else max(t_max, t)
                    continue

                # Value-change branches with body validation.
                first = tok[0] if tok else ''
                if first in '01xXzZ' and len(tok) > 1:
                    if t_min is None:
                        saw_initial_data = True
                elif first in 'bB':
                    bits = tok[1:]
                    if not bits or any(c not in '01xXzZ' for c in bits):
                        continue
                    sym = _next()
                    if _is_struct(sym):
                        if sym is not None:
                            pushback.append(sym)
                        continue
                    if t_min is None:
                        saw_initial_data = True
                elif first in 'rR':
                    body = tok[1:]
                    if len(body) > _REAL_MAX_LEN or not _REAL_RE.match(body):
                        continue
                    sym = _next()
                    if _is_struct(sym):
                        if sym is not None:
                            pushback.append(sym)
                        continue
                    if t_min is None:
                        saw_initial_data = True
                elif first == 'p':
                    state = tok[1:] if len(tok) > 1 else ''
                    if not state or any(c not in _PORT_STATE for c in state):
                        continue
                    _s0 = _next()
                    if _s0 is None or len(_s0) != 1 or _s0 not in '01234567':
                        if _s0 is not None:
                            pushback.append(_s0)
                        continue
                    _s1 = _next()
                    if _s1 is None or len(_s1) != 1 or _s1 not in '01234567':
                        if _s1 is not None:
                            pushback.append(_s1)
                        pushback.append(_s0)
                        continue
                    sym = _next()
                    if _is_struct(sym):
                        if sym is not None:
                            pushback.append(sym)
                        pushback.append(_s1)
                        pushback.append(_s0)
                        continue
                    if t_min is None:
                        saw_initial_data = True
        finally:
            close = getattr(raw, 'close', None)
            if close is not None:
                close()

        if t_min is None and saw_initial_data:
            t_min = t_max = 0
        return t_min, t_max



# -- Subcommands -------------------------------------------------------------

_DEFAULT_LIMIT = 200


def _json(obj):
    """Compact JSON for agent use."""
    print(json.dumps(obj, ensure_ascii=False, separators=(',', ':')))


def _limit(args, cmd):
    """Resolve global output limit. --verbose disables truncation unless an
    explicit --limit was supplied. --limit 0 always means unlimited."""
    val = getattr(args, 'limit', None)
    if val is None:
        return 0 if getattr(args, 'verbose', False) else _DEFAULT_LIMIT
    if val < 0:
        raise _TimeParseError('limit must be non-negative; got {}'.format(val))
    return val


def _clip(seq, limit):
    if limit == 0:
        return seq, False
    return seq[:limit], len(seq) > limit


def _trunc_line(shown, total, noun):
    return '... truncated: {}/{} {} shown.'.format(shown, total, noun)


def _trunc_line_lower_bound(shown, total, noun):
    """Truncation line when scanning stopped at the first unshown result.

    Used by streaming commands where --limit is an execution bound, not just
    an output bound. `total` is a lower bound (normally shown + 1),
    not the exact global result count.
    """
    return '... truncated: {}/{}+ {} shown.'.format(shown, total, noun)


def _total_json_fields(total, truncated):
    """Return JSON count fields for exact vs early-stopped result sets.

    When truncated is true, total is only a lower bound (usually limit+1).
    Keeping it numeric is convenient for agents, while total_is_exact prevents
    consumers from treating it as the real global count.
    """
    return {'total': total, 'total_is_exact': not truncated}


def _count_label(shown, total, truncated):
    """Human count label for result headers."""
    return '{}+'.format(total) if truncated else str(total)


def _selected_sids(vcd, sids):
    """Return an explicit set of selected signal ids."""
    return set(vcd.signals.keys()) if sids is None else set(sids)


def _fmt_maybe(value, info):
    return fmt_val(value, info) if value is not None else '(undef)'


def _time_pair(prefix, t, ts):
    """Return both integer ticks and human-readable time for JSON outputs."""
    return {prefix + '_ticks': t, prefix + '_h': fmt_time(t, ts) if t is not None else None}


def _build_snapshot(vcd, t_at, sids=None):
    """Replay from start through t_at, return known {sig_id: value} only."""
    state = {}
    for _t, sid, val in vcd.iter_events(0, t_at, sids):
        state[sid] = val
    return state


def _build_snapshot_before(vcd, t_at, sids=None):
    """Replay from start up to, but excluding, t_at.

    Used by search --changed. A value_change exactly at --begin must remain
    observable as a transition. Because VCD timestamps are integer ticks, the
    exclusive snapshot is simply the inclusive snapshot at t_at - 1. At t=0
    there is no prior state; initialization is handled explicitly by the
    changed-mode loop and is not reported as a real change.
    """
    if t_at <= 0:
        return {}
    return _build_snapshot(vcd, t_at - 1, sids)


def _parse_target_value(text):
    """Parse search/condition target once with bounded cost.

    Returns (target_raw, target_int):

      - Numeric targets (decimal, 0x..., 0b..., b...) get target_int and are
        matched only by numeric equality.
      - 4-state binary literals with x/z keep a raw bit-string target. Explicit
        binary prefixes are stripped because VCD stores vector values as
        ``1x0`` internally, not ``b1x0``.

    Invalid hex and negative decimal targets are rejected rather than silently
    producing no matches; VCD value_change text is unsigned, and x/z literals
    should be written in binary form (e.g. b1x0z).
    """
    if text is None:
        raise _ValueParseError('target value must not be empty')
    raw = str(text).lower().strip()
    if not raw:
        raise _ValueParseError('target value must not be empty')
    if len(raw) > MAX_VALUE_ARG_LEN:
        raise _ValueParseError(
            'target value too long; max length is {}'.format(MAX_VALUE_ARG_LEN))

    if raw.startswith('-'):
        raise _ValueParseError(
            'negative target values are not supported for VCD signal matching')

    if raw.startswith('0x'):
        body = raw[2:]
        if not body:
            raise _ValueParseError('hex target must contain at least one digit')
        if len(body) > MAX_HEX_VALUE_DIGITS:
            raise _ValueParseError(
                'hex target too wide; max hex digits is {}'.format(MAX_HEX_VALUE_DIGITS))
        try:
            return raw, int(raw, 16)
        except ValueError:
            raise _ValueParseError(
                'invalid hex target {!r}; x/z literals must use binary form like b1x0z'.format(text))

    if raw.startswith('0b'):
        body = raw[2:]
        if not body:
            raise _ValueParseError('binary target must contain at least one bit')
        if len(body) > MAX_SIGNAL_WIDTH:
            raise _ValueParseError(
                'binary target too wide; max bits is {}'.format(MAX_SIGNAL_WIDTH))
        try:
            return body, int(body, 2)
        except ValueError:
            if all(c in '01xz' for c in body):
                return body, None
            raise _ValueParseError(
                'invalid binary target {!r}; expected only 0/1/x/z'.format(text))

    if raw.startswith('b'):
        body = raw[1:]
        if not body:
            raise _ValueParseError('binary target must contain at least one bit')
        if len(body) > MAX_SIGNAL_WIDTH:
            raise _ValueParseError(
                'binary target too wide; max bits is {}'.format(MAX_SIGNAL_WIDTH))
        try:
            return body, int(body, 2)
        except ValueError:
            if all(c in '01xz' for c in body):
                return body, None
            raise _ValueParseError(
                'invalid binary target {!r}; expected only 0/1/x/z'.format(text))

    # Bare target: decimal numeric if possible, otherwise literal 4-state
    # string (e.g. ``1x0``). Cap pure decimal digit count before int().
    if raw.startswith('+'):
        raise _ValueParseError(
            'signed target values are not supported; write unsigned values')
    if raw.isdigit() and len(raw) > MAX_DECIMAL_VALUE_DIGITS:
        raise _ValueParseError(
            'decimal target too long; max digits is {}'.format(MAX_DECIMAL_VALUE_DIGITS))
    try:
        return raw, int(raw)
    except ValueError:
        if len(raw) > MAX_SIGNAL_WIDTH:
            raise _ValueParseError(
                'literal target too wide; max characters is {}'.format(MAX_SIGNAL_WIDTH))
        return raw, None


def _is_4state_bits(text):
    return text is not None and text != '' and all(c in '01xz' for c in text)


def _left_extend_bits(bits, width):
    """Apply VCD vector left-extension to a 4-state bit string.

    When a dumped vector is shorter than its declared width, IEEE VCD
    semantics extend the MSB leftward: x extends with x, z with z, and
    0/1 with 0. Use the same rule for user 4-state targets so a condition
    such as data=b1x0 can match an 8-bit stored value 000001x0 without
    asking the Agent to spell out every leading zero.
    """
    if width is None or len(bits) >= width:
        return bits
    msb = bits[0]
    pad = msb if msb in ('x', 'z') else '0'
    return pad * (width - len(bits)) + bits


def _value_matches(value, target_raw, target_int, width=None):
    """Match a recorded value against a parsed search target.

    Numeric targets (decimal/hex/binary without x/z) match only by numeric
    equality, avoiding the decimal/binary collision where target 10 would
    otherwise raw-match a 2-bit value "10".

    Non-numeric 4-state targets (for example b1x0 -> raw "1x0") match as
    bit patterns. If the signal width is known, both the dumped value and the
    target are left-extended to that width using VCD rules before comparison.
    This preserves exact x/z semantics while avoiding the need to write every
    leading zero for wide buses. Non-bit-string literals fall back to exact
    string equality.
    """
    if target_int is not None:
        iv = val_to_int(value)
        return iv is not None and iv == target_int
    if width is not None and _is_4state_bits(value) and _is_4state_bits(target_raw):
        if len(target_raw) > width:
            return False
        return _left_extend_bits(value, width) == _left_extend_bits(target_raw, width)
    return value == target_raw


_COND_RE = re.compile(r'^\s*(.+?)\s*(==|=|!=)\s*(.+?)\s*$')


def _has_unknown(value):
    """True when a VCD value is unknown/ambiguous for negative predicates."""
    return value is None or 'x' in value or 'z' in value


def _condition_match(value, op, target_raw, target_int, width=None):
    """Evaluate one resolved condition against a raw VCD value.

    Equality reuses the existing two-mode value matcher, so numeric targets
    are compared numerically and mixed x/z literals are compared as 4-state
    bit patterns, width-aware when the signal width is available.

    Inequality is deliberately stricter than `not _value_matches(...)`:
    x/z/undef do NOT satisfy `!=`. In RTL debug, unknown is not evidence that
    a signal is definitely different from a value. Users who want unknowns
    should ask for them explicitly, e.g. `valid=x`.
    """
    if value is None:
        return False
    if op in ('=', '=='):
        return _value_matches(value, target_raw, target_int, width)
    if op == '!=':
        if _has_unknown(value):
            return False
        return not _value_matches(value, target_raw, target_int, width)
    raise AssertionError('unsupported condition operator {}'.format(op))


def _parse_conditions(text):
    """Parse comma-separated AND conditions into unresolved condition dicts."""
    if text is None or not str(text).strip():
        raise _ConditionParseError('search requires --condition')
    conditions = []
    for item in str(text).split(','):
        item = item.strip()
        if not item:
            continue
        m = _COND_RE.match(item)
        if not m:
            raise _ConditionParseError(
                'invalid condition {!r}; expected SIG=VAL, SIG==VAL, or SIG!=VAL'.format(item))
        sig_pat = m.group(1).strip()
        op = m.group(2)
        val_text = m.group(3).strip()
        if not sig_pat or not val_text:
            raise _ConditionParseError(
                'invalid empty signal/value in condition {!r}'.format(item))
        target_raw, target_int = _parse_target_value(val_text)
        conditions.append({
            'pattern': sig_pat,
            'op': op,
            'target_raw': target_raw,
            'target_int': target_int,
            'original': item,
            'value_text': val_text,
        })
    if not conditions:
        raise _ConditionParseError('search requires at least one condition')
    return conditions


def _resolve_one_signal(vcd, pattern, role):
    """Resolve a condition/trigger pattern to exactly one signal id.

    Matching normally follows VCDParser.match(): substring unless '*' or '?'
    is present. For condition/trigger positions, however, an exact full path
    should win over substring matches. Otherwise a precise path like
    'tb.u.rd_valid' would be rejected merely because 'tb.u.rd_valid0' exists.
    """
    pat = str(pattern).strip()
    pl = pat.lower()
    exact = set()
    if '*' not in pat and '?' not in pat:
        for sid, info in vcd.signals.items():
            for path in info['aliases']:
                if path.lower() == pl:
                    exact.add(sid)
        if len(exact) == 1:
            return next(iter(exact))
        if len(exact) > 1:
            examples = [vcd.signals[s]['path']
                        for s in sorted(exact, key=lambda sid: vcd.signals[sid]['path'])[:5]]
            raise _ConditionParseError(
                '{} pattern {!r} exactly matches {} signals; use list to choose a more specific name, examples: {}'.format(
                    role, pattern, len(exact), ', '.join(examples)))

    sids = vcd.match([pattern])
    if not sids:
        raise _ConditionParseError('{} pattern {!r} matches no signals'.format(role, pattern))
    if len(sids) != 1:
        examples = [vcd.signals[s]['path']
                    for s in sorted(sids, key=lambda sid: vcd.signals[sid]['path'])[:5]]
        extra = ', examples: {}'.format(', '.join(examples)) if examples else ''
        raise _ConditionParseError(
            '{} pattern {!r} matches {} signals; use list to choose a more specific name{}'.format(
                role, pattern, len(sids), extra))
    return next(iter(sids))


def _resolve_conditions(vcd, text):
    """Parse and resolve condition signal patterns to signal ids."""
    resolved = []
    seen = set()
    for c in _parse_conditions(text):
        sid = _resolve_one_signal(vcd, c['pattern'], 'condition signal')
        key = (sid, c['op'], c['target_raw'], c['target_int'])
        if key in seen:
            continue
        seen.add(key)
        c = dict(c)
        c['sid'] = sid
        c['path'] = vcd.signals[sid]['path']
        c['width'] = vcd.signals[sid]['width']
        resolved.append(c)
    return resolved


def _resolve_show_sids(vcd, show_patterns):
    """Resolve --show patterns to one or more signal ids.

    Show positions are allowed to match multiple signals, but an exact full
    path still wins over substring matching for that specific pattern. This
    keeps `--show tb.data` from unexpectedly also selecting `tb.data_out`;
    users who want broad matching can still write `--show data` or use glob
    patterns such as `--show "*data*"`.
    """
    if not show_patterns:
        return []
    # Normalize even for list inputs.  argparse already does this for CLI
    # strings, but repeating the bounded, idempotent normalization keeps the
    # helper safe for programmatic callers as well.
    pats = _normalize_filter_patterns(show_patterns)
    if not pats:
        return []

    selected = set()
    missing = []
    for pat in pats:
        pat_text = str(pat).strip()
        exact = set()
        if '*' not in pat_text and '?' not in pat_text:
            pl = pat_text.lower()
            for sid, info in vcd.signals.items():
                for path in info['aliases']:
                    if path.lower() == pl:
                        exact.add(sid)
            if exact:
                selected.update(exact)
                continue

        matched = vcd.match([pat_text])
        if matched:
            selected.update(matched)
        else:
            missing.append(pat_text)

    if missing:
        raise _ConditionParseError(
            '--show matches no signals: {}'.format(', '.join(missing)))
    if not selected:
        raise _ConditionParseError('--show matches no signals')
    return sorted(selected, key=lambda sid: vcd.signals[sid]['path'])


def _conditions_hold(state, conditions):
    for c in conditions:
        if not _condition_match(
                state.get(c['sid']), c['op'], c['target_raw'],
                c['target_int'], c.get('width')):
            return False
    return True


def _condition_label(conditions):
    return ','.join(c['original'] for c in conditions)


def _condition_result_text(conditions):
    return ','.join('{}{}{}'.format(c['path'], c['op'], c['value_text']) for c in conditions)


def _show_values(vcd, state, show_sids, verbose=False):
    """Return (values, meta) for show signals in current state.

    The return shape is intentionally stable regardless of verbose. meta is
    None unless verbose=True. This avoids type-dependent unpacking in search.
    """
    values = {}
    meta = {} if verbose else None
    for sid in show_sids:
        info = vcd.signals[sid]
        path = info['path']
        raw = state.get(sid)
        values[path] = fmt_val(raw, info) if raw is not None else '(undef)'
        if verbose:
            meta[path] = {'raw': raw, 'width': info['width'], 'type': info.get('type', 'wire')}
    return values, meta


def _values_text(values):
    return ' '.join('{}={}'.format(k, v) for k, v in values.items())


def _search_end_time(vcd, t0, t1):
    if t1 is not None:
        return t1
    _mn, mx = vcd.scan_time_range()
    if mx is None:
        raise _ConditionParseError(
            'search cannot evaluate condition: VCD data section contains no value changes')
    return mx


def _event_groups(vcd, t0, t1, sids):
    """Yield (time, [(sid, val), ...]) groups in time order."""
    cur_t = None
    group = []
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        if cur_t is None:
            cur_t = t
        if t != cur_t:
            yield cur_t, group
            cur_t, group = t, []
        group.append((sid, val))
    if cur_t is not None:
        yield cur_t, group


def _summary_rows(vcd, t0, t1, sids):
    """Return (rows, counts) for window summary.

    Static means known at t0 and no value changes after t0 inside the window.
    Undefined means selected but not known at t0 and no value changes inside
    the window. No unknown values are invented.

    For 1-bit signals, rise/fall counts are reported for clean 0->1 and 1->0
    transitions only. x/z-related transitions still count as changes, but not
    as rises/falls.
    """
    selected = _selected_sids(vcd, sids)
    initial = _build_snapshot(vcd, t0, selected)
    stats = {}
    for sid, val in initial.items():
        info = vcd.signals[sid]
        stats[sid] = {
            'changes': 0, 'first_at': None, 'last_at': None,
            'initial': val, 'last': val, 'unique': {val},
            'prev': val, 'rise_count': 0 if info['width'] == 1 else None,
            'fall_count': 0 if info['width'] == 1 else None,
        }
    for t, group in _event_groups(vcd, t0, t1, selected):
        if t <= t0:
            continue
        for sid, val in group:
            info = vcd.signals[sid]
            is_scalar = info['width'] == 1
            if sid not in stats:
                stats[sid] = {
                    'changes': 0, 'first_at': None, 'last_at': None,
                    'initial': None, 'last': None, 'unique': set(),
                    'prev': None, 'rise_count': 0 if is_scalar else None,
                    'fall_count': 0 if is_scalar else None,
                }
            s = stats[sid]
            prev = s.get('prev')
            if is_scalar:
                if prev == '0' and val == '1':
                    s['rise_count'] += 1
                elif prev == '1' and val == '0':
                    s['fall_count'] += 1
            s['changes'] += 1
            if s['first_at'] is None:
                s['first_at'] = t
            s['last_at'] = t
            s['last'] = val
            s['prev'] = val
            s['unique'].add(val)

    rows = []
    for sid in sorted(stats, key=lambda x: vcd.signals[x]['path']):
        info = vcd.signals[sid]
        s = stats[sid]
        kind = 'active' if s['changes'] else 'static'
        row = {
            'kind': kind,
            'path': info['path'],
            'value': fmt_val(s['last'], info) if kind == 'static' else None,
            'changes': s['changes'],
            'rise_count': s['rise_count'],
            'fall_count': s['fall_count'],
            'init': _fmt_maybe(s['initial'], info),
            'last': _fmt_maybe(s['last'], info),
        }
        if s['first_at'] is not None:
            row['first_at_ticks'] = s['first_at']
            row['first_at'] = fmt_time(s['first_at'], vcd.ts_sec)
            row['first_at_h'] = row['first_at']
            row['last_at_ticks'] = s['last_at']
            row['last_at'] = fmt_time(s['last_at'], vcd.ts_sec)
            row['last_at_h'] = row['last_at']
        if s['unique']:
            row['unique'] = len(s['unique'])
        row['_width'] = info['width']
        row['_type'] = info.get('type', 'wire')
        rows.append(row)

    undefined = sorted(selected - set(stats), key=lambda x: vcd.signals[x]['path'])
    counts = {
        'selected': len(selected), 'defined': len(stats), 'undefined': len(undefined),
        'active': sum(1 for r in rows if r['kind'] == 'active'),
        'static': sum(1 for r in rows if r['kind'] == 'static'),
    }
    return rows, undefined, counts

def _public_row(row, verbose=False):
    r = dict(row)
    width = r.pop('_width', None)
    typ = r.pop('_type', None)
    if verbose:
        r['width'] = width
        r['type'] = typ
    return r


def cmd_info(vcd, args):
    t_min, t_max = vcd.scan_time_range()
    ts = vcd.ts_sec
    synth = [s for s in vcd.signals.values() if s.get('synthesized')]
    r = {
        'file': vcd.path,
        'size_bytes': os.path.getsize(vcd.path),
        'timescale': vcd.ts_str.replace('$timescale', '').replace('$end', '').strip(),
        # Provenance metadata from VCD header (IEEE 1364-2005 18.2.3.1-3).
        # Tells the agent which simulator produced the file and when, so
        # downstream debug can apply tool-specific heuristics (e.g. QuestaSim
        # bit-explodes wide buses but iverilog doesn't).
        'date': vcd.date,
        'version': vcd.version,
        'comments': list(vcd.comments),
        'signal_count': len(vcd.signals),
        'reference_count': vcd.raw_var_count,
        'synthesized_buses': len(synth),
        'var_types': dict(sorted(vcd.raw_type_counts.items(), key=lambda x: -x[1])),
        'time_min': fmt_time(t_min, ts) if t_min is not None else None,
        'time_min_ticks': t_min,
        'time_min_h': fmt_time(t_min, ts) if t_min is not None else None,
        'time_max': fmt_time(t_max, ts) if t_max is not None else None,
        'time_max_ticks': t_max,
        'time_max_h': fmt_time(t_max, ts) if t_max is not None else None,
        'duration': fmt_time(t_max - t_min, ts) if t_min is not None and t_max is not None else None,
        'duration_ticks': (t_max - t_min) if t_min is not None and t_max is not None else None,
        'duration_h': fmt_time(t_max - t_min, ts) if t_min is not None and t_max is not None else None,
        # Use declaration-time scope metadata instead of splitting public
        # paths on '.'. Escaped identifiers may legally contain dots;
        # path.split('.') would invent fake hierarchy such as tb.\foo.
        'scopes': sorted(set(
            sc for v in vcd.signals.values() for sc in v.get('scopes', []) if sc
        )),
    }
    if args.json:
        _json(r)
    else:
        print('File      : {}'.format(r['file']))
        print('Size      : {:,} bytes'.format(r['size_bytes']))
        if r['date']:
            print('Date      : {}'.format(r['date']))
        if r['version']:
            print('Tool      : {}'.format(r['version']))
        print('Timescale : {}'.format(r['timescale']))
        if r['signal_count'] == r['reference_count']:
            print('Signals   : {}'.format(r['signal_count']))
        elif r['synthesized_buses']:
            print('Signals   : {} ({} $var decls, {} reassembled as bit-buses)'.format(
                r['signal_count'], r['reference_count'], r['synthesized_buses']))
        else:
            print('Signals   : {} unique ({} $var refs via aliases)'.format(
                r['signal_count'], r['reference_count']))
        print('Types     : {}'.format(', '.join('{}={}'.format(k, v) for k, v in r['var_types'].items())))
        print('Time      : {} ~ {} ({})'.format(r['time_min'], r['time_max'], r['duration']))
        for s in r['scopes']:
            print('  scope: {}'.format(s))
        if r['comments'] and getattr(args, 'verbose', False):
            # Comments verbose-only: typical files have boilerplate
            # ("Generated by ..."), worth showing only on demand.
            print('Comments  :')
            for c in r['comments']:
                print('  - {}'.format(c))


def cmd_list(vcd, args):
    limit = _limit(args, 'list')
    sids = vcd.match(args.filter)
    entries = []
    for sid, info in vcd.signals.items():
        if sids is not None and sid not in sids:
            continue
        vtype = info.get('type', 'wire')
        for path in info['aliases']:
            e = {'path': path, 'width': info['width'], 'type': vtype}
            if getattr(args, 'verbose', False):
                e['id'] = sid
                if info.get('synthesized'):
                    e['synthesized'] = True
                    e['raw_bits'] = info.get('raw_bits')
            entries.append(e)
    entries.sort(key=lambda e: e['path'])
    shown, trunc = _clip(entries, limit)
    if args.json:
        _json({'total': len(entries), 'shown': len(shown), 'truncated': trunc, 'signals': shown})
    else:
        print('Matched: {}/{}'.format(len(entries), len(vcd.signals)))
        for e in shown:
            print('  {:<60} {:>5}  {}'.format(e['path'], e['width'], e['type']))
        if trunc:
            print(_trunc_line(len(shown), len(entries), 'signals'))


def cmd_dump(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    if t1 is not None and t1 < t0:
        raise _TimeParseError('end time must be >= begin time')
    sids = vcd.match(args.filter)
    limit = _limit(args, 'dump')
    total = 0
    truncated = False
    events = []
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        total += 1
        if limit != 0 and len(events) >= limit:
            truncated = True
            break
        info = vcd.signals[sid]
        e = {'time': t, 'time_ticks': t, 'time_h': fmt_time(t, ts),
             'path': info['path'], 'value': fmt_val(val, info)}
        if getattr(args, 'verbose', False):
            e['width'] = info['width']
            e['type'] = info.get('type', 'wire')
        events.append(e)
    if args.json:
        obj = {'shown': len(events), 'truncated': truncated, 'events': events}
        obj.update(_total_json_fields(total, truncated))
        _json(obj)
        return
    if not events:
        print('(no changes in range)')
        return
    cur = None
    for e in events:
        if e['time'] != cur:
            cur = e['time']
            print('T={}'.format(e['time_h']))
        if getattr(args, 'verbose', False):
            print('  {:<55} w={} {} = {}'.format(e['path'], e.get('width'), e.get('type'), e['value']))
        else:
            print('  {:<55} = {}'.format(e['path'], e['value']))
    if truncated:
        print(_trunc_line_lower_bound(len(events), total, 'events'))


def cmd_summary(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    if t1 is not None and t1 < t0:
        raise _TimeParseError('end time must be >= begin time')
    sids = vcd.match(args.filter)
    selected = _selected_sids(vcd, sids)
    rows, undef_sids, counts = _summary_rows(vcd, t0, t1, selected)
    active = [r for r in rows if r['kind'] == 'active']
    static = [r for r in rows if r['kind'] == 'static']
    ordered = active + static
    if getattr(args, 'verbose', False):
        for sid in undef_sids:
            info = vcd.signals[sid]
            ordered.append({'kind': 'undefined', 'path': info['path'], 'value': None,
                            'changes': 0, 'rise_count': 0 if info['width'] == 1 else None,
                            'fall_count': 0 if info['width'] == 1 else None,
                            'init': '(undef)', 'last': '(undef)',
                            '_width': info['width'], '_type': info.get('type', 'wire')})
    limit = _limit(args, 'summary')
    shown, trunc = _clip(ordered, limit)
    begin_h = fmt_time(t0, ts)
    end_h = fmt_time(t1, ts) if t1 is not None else None
    if args.json:
        _json({'window': {'begin': begin_h, 'end': end_h,
                          'begin_ticks': t0, 'begin_h': begin_h,
                          'end_ticks': t1, 'end_h': end_h}, **counts,
               'shown': len(shown), 'truncated': trunc,
               'rows': [_public_row(r, getattr(args, 'verbose', False)) for r in shown]})
        return
    print('Window: {}..{}'.format(begin_h, end_h if end_h is not None else '(end)'))
    print('Selected: {}, Defined: {}, Undefined: {}'.format(
        counts['selected'], counts['defined'], counts['undefined']))
    print('Active: {}, Static: {}'.format(counts['active'], counts['static']))
    current = None
    for r in shown:
        if r['kind'] != current:
            current = r['kind']
            print('\n{}'.format(current.upper()))
        if r['kind'] == 'active':
            if getattr(args, 'verbose', False):
                edge = '' if r.get('rise_count') is None else ' r={} f={}'.format(
                    r.get('rise_count', 0), r.get('fall_count', 0))
                print('  {:<45} w={} {} chg={}{} init={} last={} first@{} last@{} uniq={}'.format(
                    r['path'], r['_width'], r['_type'], r['changes'], edge, r['init'], r['last'],
                    r.get('first_at', '-'), r.get('last_at', '-'), r.get('unique', 0)))
            else:
                edge = '' if r.get('rise_count') is None else ' r={} f={}'.format(
                    r.get('rise_count', 0), r.get('fall_count', 0))
                print('  {:<45} chg={}{} init={} last={}'.format(
                    r['path'], r['changes'], edge, r['init'], r['last']))
        elif r['kind'] == 'static':
            if getattr(args, 'verbose', False):
                print('  {:<45} w={} {} value={}'.format(r['path'], r['_width'], r['_type'], r['value']))
            else:
                print('  {:<45} value={}'.format(r['path'], r['value']))
        else:
            print('  {:<45} w={} {}'.format(r['path'], r['_width'], r['_type']))
    if not rows and not undef_sids:
        print('(no selected signals)')
    if trunc:
        print(_trunc_line(len(shown), len(ordered), 'rows'))


def cmd_snapshot(vcd, args):
    ts = vcd.ts_sec
    t_at = parse_time(args.at, ts)
    sids0 = vcd.match(args.filter)
    selected = _selected_sids(vcd, sids0)
    state = _build_snapshot(vcd, t_at, selected)
    rows = []
    for sid in sorted(state, key=lambda s: vcd.signals[s]['path']):
        info = vcd.signals[sid]
        r = {'path': info['path'], 'value': fmt_val(state[sid], info)}
        if getattr(args, 'verbose', False):
            r['width'] = info['width']
            r['type'] = info.get('type', 'wire')
        rows.append(r)
    undef = sorted(selected - set(state), key=lambda s: vcd.signals[s]['path'])
    if getattr(args, 'verbose', False):
        for sid in undef:
            info = vcd.signals[sid]
            rows.append({'path': info['path'], 'value': None, 'undefined': True,
                         'width': info['width'], 'type': info.get('type', 'wire')})
    limit = _limit(args, 'snapshot')
    shown, trunc = _clip(rows, limit)
    if args.json:
        _json({'at': fmt_time(t_at, ts), 'at_ticks': t_at, 'at_h': fmt_time(t_at, ts),
               'selected': len(selected), 'known': len(state),
               'undefined': len(undef), 'shown': len(shown), 'truncated': trunc,
               'signals': shown})
        return
    if not state:
        print('No known values at {}.'.format(fmt_time(t_at, ts)))
    else:
        print('Known snapshot @ {}'.format(fmt_time(t_at, ts)))
    if getattr(args, 'verbose', False):
        print('Selected: {}, Known: {}, Undefined: {}'.format(len(selected), len(state), len(undef)))
    for r in shown:
        if r.get('undefined'):
            print('  {:<55} = (undef)'.format(r['path']))
        elif getattr(args, 'verbose', False):
            print('  {:<55} w={} {} = {}'.format(r['path'], r.get('width'), r.get('type'), r['value']))
        else:
            print('  {:<55} = {}'.format(r['path'], r['value']))
    if trunc:
        print(_trunc_line(len(shown), len(rows), 'signals'))


def cmd_compare(vcd, args):
    ts = vcd.ts_sec
    parts = args.at.split(',')
    if len(parts) != 2:
        raise _TimeParseError(
            '--at needs two times separated by comma, e.g. --at 17.5us,17.7us')
    ta, tb = parse_time(parts[0].strip(), ts), parse_time(parts[1].strip(), ts)
    if tb < ta:
        raise _TimeParseError('second compare time must be >= first compare time')
    sids = vcd.match(args.filter)
    sa = _build_snapshot(vcd, ta, sids)
    sb = _build_snapshot(vcd, tb, sids)
    diffs = []
    for sid in sorted(set(sa) | set(sb), key=lambda s: vcd.signals[s]['path']):
        va, vb = sa.get(sid), sb.get(sid)
        if va != vb:
            info = vcd.signals[sid]
            d = {'path': info['path'],
                 'at_t1': fmt_val(va, info) if va is not None else '(undef)',
                 'at_t2': fmt_val(vb, info) if vb is not None else '(undef)'}
            if getattr(args, 'verbose', False):
                d['width'] = info['width']
                d['type'] = info.get('type', 'wire')
            diffs.append(d)
    limit = _limit(args, 'compare')
    shown, trunc = _clip(diffs, limit)
    if args.json:
        _json({'t1': fmt_time(ta, ts), 't1_ticks': ta, 't1_h': fmt_time(ta, ts),
               't2': fmt_time(tb, ts), 't2_ticks': tb, 't2_h': fmt_time(tb, ts),
               'total': len(diffs), 'shown': len(shown), 'truncated': trunc,
               'diffs': shown})
    else:
        print('Compare: {} vs {}'.format(fmt_time(ta, ts), fmt_time(tb, ts)))
        print('{} changed, {} unchanged'.format(len(diffs), len(set(sa) | set(sb)) - len(diffs)))
        for d in shown:
            print('  {:<48} {} -> {}'.format(d['path'], d['at_t1'], d['at_t2']))
        if trunc:
            print(_trunc_line(len(shown), len(diffs), 'diffs'))


def cmd_search(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1_raw = parse_time(args.end, ts) if args.end else None
    t1 = _search_end_time(vcd, t0, t1_raw)
    if t1 < t0:
        raise _TimeParseError('end time must be >= begin time')

    conditions = _resolve_conditions(vcd, args.condition)
    show_sids = _resolve_show_sids(vcd, args.show)
    changed_sid = _resolve_one_signal(vcd, args.changed, 'changed signal') if args.changed else None
    if changed_sid is not None and not show_sids:
        show_sids = [changed_sid]

    selected = set(c['sid'] for c in conditions)
    selected.update(show_sids)
    if changed_sid is not None:
        selected.add(changed_sid)

    # Inclusive snapshot is correct for interval/segment modes: they ask
    # what state holds at t0.  changed mode needs the state before t0 so
    # an edge exactly at --begin remains observable.
    state = (_build_snapshot_before(vcd, t0, selected)
             if changed_sid is not None else _build_snapshot(vcd, t0, selected))
    limit = _limit(args, 'search')
    verbose = getattr(args, 'verbose', False)
    cond_label = _condition_label(conditions)
    cond_text = _condition_result_text(conditions)

    if changed_sid is not None:
        events = []
        total = 0
        truncated = False
        for t, group in _event_groups(vcd, t0, t1, selected):
            changed = set()
            for sid, val in group:
                old_val = state.get(sid)
                # For ordinary state-carrying signals, --changed means the
                # value is different from the previous known state. VCD
                # variables of type `event` are different: every value_change
                # token is a trigger even if the dumped marker text repeats.
                # In both cases, t=0 dumpvars-style initialization is not a
                # real change.
                if t == 0 and old_val is None:
                    pass
                elif vcd.signals[sid].get('type') == 'event':
                    changed.add(sid)
                elif old_val is None:
                    # First observed value for an ordinary state signal is a
                    # definition, not evidence of a transition.  This matters
                    # when --begin is after time 0 and a signal is first dumped
                    # inside the query window.
                    pass
                elif old_val != val:
                    changed.add(sid)
                state[sid] = val
            if changed_sid not in changed:
                continue
            if not _conditions_hold(state, conditions):
                continue
            values, meta = _show_values(vcd, state, show_sids, verbose)
            event = {'time_ticks': t, 'time_h': fmt_time(t, ts), 'values': values}
            if verbose:
                event['meta'] = meta
            total += 1
            if limit != 0 and len(events) >= limit:
                truncated = True
                break
            events.append(event)
        if args.json:
            obj = {'mode': 'event', 'condition': cond_label,
                   'condition_resolved': cond_text,
                   'changed': vcd.signals[changed_sid]['path'],
                   'show': [vcd.signals[sid]['path'] for sid in show_sids],
                   'begin_ticks': t0, 'begin_h': fmt_time(t0, ts),
                   'end_ticks': t1, 'end_h': fmt_time(t1, ts),
                   'shown': len(events), 'truncated': truncated,
                   'events': events}
            obj.update(_total_json_fields(total, truncated))
            _json(obj)
            return
        if events:
            print('Found: {} event(s)'.format(_count_label(len(events), total, truncated)))
            for e in events:
                print('  T={:<12} {}'.format(e['time_h'], _values_text(e['values'])))
            if truncated:
                print(_trunc_line_lower_bound(len(events), total, 'events'))
        else:
            print('No event in {}..{} where {} changed and {}.'.format(
                fmt_time(t0, ts), fmt_time(t1, ts), vcd.signals[changed_sid]['path'], cond_text))
        return

    # Interval/segment mode. A segment is an interval further split whenever
    # the displayed show-value tuple changes while the condition remains true.
    has_show = bool(show_sids)
    active = _conditions_hold(state, conditions)
    seg_start = t0 if active else None
    seg_values = None
    seg_meta = None
    if active and has_show:
        seg_values, seg_meta = _show_values(vcd, state, show_sids, verbose)

    results = []
    total = 0
    truncated = False

    def emit_interval(a, b):
        return {'begin_ticks': a, 'begin_h': fmt_time(a, ts),
                'end_ticks': b, 'end_h': fmt_time(b, ts)}

    def append_result(row):
        nonlocal total, truncated
        total += 1
        if limit != 0 and len(results) >= limit:
            truncated = True
            return True
        results.append(row)
        return False

    for t, group in _event_groups(vcd, t0, t1, selected):
        # _build_snapshot(vcd, t0) already applied all value_changes at t0.
        # Replaying the same group is idempotent for legal VCD, but skipping
        # it avoids duplicate work for large initial dumps at the window start.
        if t <= t0:
            continue
        # Interval/segment mode only needs the current cross-section state;
        # changed-mode edge detection is handled in its own branch above.
        for sid, val in group:
            state[sid] = val

        cond_ok = _conditions_hold(state, conditions)
        if not has_show:
            if cond_ok and not active:
                active = True
                seg_start = t
            elif not cond_ok and active:
                if append_result(emit_interval(seg_start, t)):
                    break
                active = False
                seg_start = None
            continue

        if not cond_ok:
            if active:
                row = emit_interval(seg_start, t)
                row['values'] = seg_values
                if verbose:
                    row['meta'] = seg_meta
                if append_result(row):
                    break
                active = False
                seg_start = None
                seg_values = None
                seg_meta = None
            continue

        new_values, new_meta = _show_values(vcd, state, show_sids, verbose)
        if not active:
            active = True
            seg_start = t
            seg_values = new_values
            seg_meta = new_meta
        elif new_values != seg_values:
            row = emit_interval(seg_start, t)
            row['values'] = seg_values
            if verbose:
                row['meta'] = seg_meta
            if append_result(row):
                break
            seg_start = t
            seg_values = new_values
            seg_meta = new_meta

    if active and not truncated:
        row = emit_interval(seg_start, t1)
        if has_show:
            row['values'] = seg_values
            if verbose:
                row['meta'] = seg_meta
        append_result(row)

    if args.json:
        key = 'segments' if has_show else 'intervals'
        obj = {'mode': 'segment' if has_show else 'interval',
               'condition': cond_label,
               'condition_resolved': cond_text,
               'show': [vcd.signals[sid]['path'] for sid in show_sids],
               'begin_ticks': t0, 'begin_h': fmt_time(t0, ts),
               'end_ticks': t1, 'end_h': fmt_time(t1, ts),
               'shown': len(results), 'truncated': truncated,
               key: results}
        obj.update(_total_json_fields(total, truncated))
        _json(obj)
        return

    noun = 'segment' if has_show else 'interval'
    if results:
        print('Found: {} {}(s)'.format(_count_label(len(results), total, truncated), noun))
        for r in results:
            if has_show:
                print('  {:<12}..{:<12} {}'.format(
                    r['begin_h'], r['end_h'], _values_text(r['values'])))
            else:
                print('  {:<12}..{:<12} {}'.format(r['begin_h'], r['end_h'], cond_text))
        if truncated:
            print(_trunc_line_lower_bound(len(results), total, noun + 's'))
    else:
        print('No {} in {}..{} where {}.'.format(
            noun, fmt_time(t0, ts), fmt_time(t1, ts), cond_text))

# -- CLI entry ---------------------------------------------------------------

def _add_time_args(sp):
    sp.add_argument('--begin', metavar='TIME',
                    help='start time, e.g. 0, 100ns, 17.5us (omit = from start)')
    sp.add_argument('--end', metavar='TIME',
                    help='end time, same format (omit = no upper bound)')


def _add_filter(sp):
    sp.add_argument('--filter', metavar='K1,K2,...',
                    type=_normalize_filter_patterns,
                    help='comma-separated substring/glob patterns, case-insensitive')


def _add_common(sp):
    # Also accept global-style output controls after the subcommand.
    # Defaults are SUPPRESS so values supplied before the subcommand survive.
    sp.add_argument('--json', action='store_true', default=argparse.SUPPRESS,
                    help='output compact structured JSON instead of text')
    sp.add_argument('--limit', type=int, default=argparse.SUPPRESS,
                    help='max rows/records to emit; default 200; 0 = unlimited; streaming commands stop after the first unshown result')
    sp.add_argument('--verbose', action='store_true', default=argparse.SUPPRESS,
                    help='show extra fields; if --limit is omitted, disables truncation')


def main():
    p = argparse.ArgumentParser(
        prog='vcd_analyzer',
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--json', action='store_true',
                   help='output compact structured JSON instead of text')
    p.add_argument('--limit', type=int, default=None,
                   help='max rows/records to emit; default 200; 0 = unlimited; streaming commands stop after the first unshown result')
    p.add_argument('--verbose', action='store_true',
                   help='show extra fields; if --limit is omitted, disables truncation')
    p.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    sub = p.add_subparsers(dest='cmd', metavar='<command>')

    sp = sub.add_parser('info', help='file overview: timescale, signal count, time span, scopes')
    sp.add_argument('file', metavar='<file>', help='VCD file path'); _add_common(sp)

    sp = sub.add_parser('list', help='list signals with path and bit width')
    sp.add_argument('file', metavar='<file>'); _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('dump', help='print value-change events in time order')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('summary', help='window stats: active/static/undefined selected signals')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('snapshot', help='known signal values at a given time point')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='TIME', required=True, help='time point, e.g. 17.55us')
    _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('compare', help='diff known signal values between two time points')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='T1,T2', required=True, help='two time points comma-separated, e.g. 17.5us,17.7us')
    _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('search', help='conditional search and associated signal observation')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_common(sp)
    sp.add_argument('--condition', metavar='COND', required=True,
                    help='comma-separated AND conditions, e.g. "valid=1,ready=1"; != does not match x/z/undef')
    sp.add_argument('--show', metavar='PAT1,PAT2,...', type=_normalize_filter_patterns,
                    help='signals to display while the condition holds; output segments split when shown values change')
    sp.add_argument('--changed', metavar='PATTERN',
                    help='emit events only when this signal really changes; VCD event vars count each trigger; must match exactly one signal')

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)

    try:
        vcd = VCDParser(args.file)
        cmds = {'info': cmd_info, 'list': cmd_list, 'dump': cmd_dump, 'summary': cmd_summary,
                'snapshot': cmd_snapshot, 'compare': cmd_compare, 'search': cmd_search}
        cmds[args.cmd](vcd, args)
    except FileNotFoundError as e:
        sys.exit('Error: cannot open VCD file: {}'.format(e.filename or args.file))
    except IsADirectoryError as e:
        sys.exit('Error: not a file: {}'.format(e.filename or args.file))
    except PermissionError as e:
        sys.exit('Error: permission denied: {}'.format(e.filename or args.file))
    except _TimeParseError as e:
        sys.exit('Error: ' + str(e))
    except _ValueParseError as e:
        sys.exit('Error: ' + str(e))
    except _ConditionParseError as e:
        sys.exit('Error: ' + str(e))
    except _VCDResourceError as e:
        sys.exit('Error: ' + str(e))
    except _FilterParseError as e:
        # Reaches here only if raised from VCDParser.match() at runtime;
        # argparse handles the same error when raised from type=.
        sys.exit('Error: ' + str(e))


if __name__ == '__main__':
    import signal as _sig
    if hasattr(_sig, 'SIGPIPE'):
        _sig.signal(_sig.SIGPIPE, _sig.SIG_DFL)
    try:
        main()
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        sys.exit(0)
