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
  search     <file> --condition C [--condition C ...] [--show K1,K2] [--begin T] [--end T]
                                                        Conditional search and associated signal observation

Global options:
  --json       Output compact structured JSON instead of text (time fields include *_ticks)
  --limit N    Max rows/records to emit; default 500; 0 = unlimited.
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
  --condition C   One comma-separated AND clause. Each term is a level comparison
                  (SIG=VAL, SIG==VAL, SIG!=VAL) or the edge predicate changed(SIG).
                  Condition signal patterns must match exactly one signal.
                  SIG!=VAL does not match x/z/undef; use SIG=x to search unknown.
                  Values: decimal 5, hex 0x5, binary b0101, 4-state b1x0z, real 3.14.
                  A logic signal takes bit/numeric targets, a real signal numeric ones;
                  an event variable has no level -- ask changed(SIG) instead.
                  REPEAT the flag to OR the clauses (OR-of-ANDs): the search holds
                  wherever ANY clause holds, e.g. one clause per channel to find when
                  any handshakes. There is no in-string OR ('|' / 'OR' / parentheses).
  --show K1,K2    Optional associated signals to display while condition holds;
                  segment mode splits whenever shown values change.

  changed(SIG)    An edge predicate term, true at exactly the ticks where SIG
                  transitions. It switches search to event mode (instants, not
                  intervals); every clause must then carry one, or none may.
                  First observed values and t=0 initialization are not transitions;
                  VCD event variables count each trigger. With no --show, event
                  mode shows the changed() signals.
                  changed(a),changed(b) requires both to transition on one tick.
                  Level terms in the clause read the tick's SETTLED state, so the
                  answer does not depend on the order same-tick records happen to
                  be written in; the transitioning signal itself reads the value it
                  took AT that edge, so "changed(s),s=1" means "rising edge of s".

Examples:
  vcd_analyzer info sim.vcd
  vcd_analyzer list sim.vcd --filter tdata,tvalid,tready
  vcd_analyzer dump sim.vcd --begin 17.5us --end 17.6us --filter clk,rst,state
  vcd_analyzer summary sim.vcd --filter dll_st,locked
  vcd_analyzer snapshot sim.vcd --at 17.55us --filter init_done,state
  vcd_analyzer compare sim.vcd --at 17.535us,17.56us --filter init_done,link_active,state
  vcd_analyzer search sim.vcd --condition "state=5"
  vcd_analyzer search sim.vcd --condition "arvalid=1,arready=1" --show araddr,arlen,arid
  vcd_analyzer search sim.vcd --condition "changed(data_out),valid=0" --show data_out,valid
  vcd_analyzer search sim.vcd --condition "ch0_valid=1,ch0_ready=1" --condition "ch1_valid=1,ch1_ready=1"
  vcd_analyzer search sim.vcd --condition "valid=x"
  vcd_analyzer --json summary sim.vcd --filter tvalid,tready

Notes:
  search requires at least one observed value_change in the VCD data section;
  empty waveforms are reported as an input/data issue rather than as a false
  "no match" result.

  Time windows: with no --end, the effective end is the file's last timestamp.
  With an explicit --end beyond the last timestamp, the last known state is
  extended into that window (the same last-known-value persistence used by
  snapshot/compare); a --begin past the last timestamp without --end is an
  error, while with --end it simply queries the extended window.

  Value-change fidelity: multiple value changes to a signal within one
  timestamp (legal per IEEE 1364-2005, e.g. delta-cycle style writers) are all
  emitted, in order. A record that merely re-asserts a signal's current value
  -- a consecutive duplicate, or a $dumpall/$dumpon checkpoint re-emitting the
  current value -- is a no-op and adds no change event. search's event mode
  reports one event per qualifying transition record on the same basis; a
  clause requiring SEVERAL signals to transition together reports the tick once,
  since coincidence is a property of the tick rather than of any one record.
"""

__version__ = '1.5.0'

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

# C99 printf("%g") also renders non-finite doubles as 'inf' / '-inf' / 'nan'
# (float() additionally accepts 'infinity'), and IEEE 1364's real_number is
# %g output — so these are legal value_change texts the numeric pattern above
# cannot match. This companion pattern keeps such records in the stream
# instead of silently dropping a legal dump record (the pre-fix behavior lost
# the event from dump, info's time range, and summary counts with no
# diagnostic). Equality targets still reject them in _parse_target_value:
# nan never compares equal and inf has no finite target, so no condition can
# match one — a stated limitation, not data loss.
_REAL_NONFINITE_RE = re.compile(r'^[+-]?(?:inf(?:inity)?|nan)$', re.IGNORECASE)

# Fast 4-state validation tables. str.translate() runs entirely in C, so
# "delete every allowed character, then check for an empty remainder" is the
# fastest stdlib test for "are all characters drawn from this set?". This
# replaces per-character all()/any() generator scans on the hot value-change
# path, where they accounted for tens of millions of Python-level iterations.
_DEL_4STATE_LOWER = {ord(c): None for c in '01xz'}     # canonical lowercase
_DEL_4STATE_CI = {ord(c): None for c in '01xXzZ'}      # raw VCD, case-insensitive

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


class _LimitParseError(ValueError):
    """Raised when --limit is invalid (e.g. negative). Separate from
    _TimeParseError so the two validation failures never share a message
    identity; caught in main() for a friendly CLI error."""


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
    exceed int64. Python 3.11+ imposes a built-in decimal digit limit on
    int(str) (sys.int_max_str_digits, default 4300) as a CPU-DoS countermeasure
    (bpo/GH-95770; no PEP - PEP 678 is the unrelated exception add_note()
    proposal), but we target 3.9 where int(s) is O(n^2) for huge n; even on
    3.11+ that ValueError would otherwise become an unhandled traceback.
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
    O(n^2) decimal-int and Python 3.11+ int_max_str_digits ValueError issues
    as _parse_vcd_timestamp_token. 100 digits is far beyond any legitimate
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
    # u == 's' always matches the bound below, so the loop always returns.
    for u in ('fs', 'ps', 'ns', 'us', 'ms', 's'):
        scaled = sec / _UNITS[u]
        if -1000.0 < scaled < 1000.0 or u == 's':
            return f'{scaled:g}{u}'


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
    # Show explicit unknowns instead. The over-wide case is rare, so the
    # cheap length guard runs first and skips the per-character scan for the
    # overwhelming majority of (in-width) values.
    if len(value) > width and _is_4state_bits(value):
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
        return f'{d} (0x{format(d, "x").zfill(hw)})'
    except ValueError:
        return 'b' + value


def val_to_int(value):
    """Try converting to int, None on x/z or pathologically long values.

    int(s, 2) is O(n) for base-2 (the 3.11+ int_max_str_digits limit does
    not apply to power-of-two bases) so the worst case after
    MAX_SIGNAL_WIDTH=65536 is sub-ms — but
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

    Hot path: this runs once per standalone value_change. The over-wide case
    is rare, so the cheap ``len(value) <= width`` guard short-circuits the
    overwhelming majority of calls before the per-character 4-state scan.
    """
    width = info.get('width')
    if width is None or len(value) <= width:
        return value
    vtype = info.get('type', 'wire')
    if vtype in ('real', 'realtime', 'event'):
        return value
    if _is_4state_bits(value):
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

# Bracketed size/reference range, e.g. '[7:0]'. Tolerates a single-bit range
# written as a range (handled by the caller). Anchored so '[a:b]' rejects.
_HEADER_RANGE_RE = re.compile(r'\[(\d+):(\d+)\]$')


def _collect_bracket_tokens(tokens, i):
    """Join a bracketed reference that free-format VCD may split across tokens.

    Per IEEE 1364 free-format, a reference range can be split, e.g.
    'data [7 : 0]' -> ['data', '[7', ':', '0]']. Returns (joined, next_idx)
    when tokens[i] opens a '[', else (None, i). This is module-level (rather
    than nested in _parse_header) so the one-line fast path and the generic
    token parser share one definition and cannot drift apart.
    """
    if i >= len(tokens) or not tokens[i].startswith('['):
        return None, i
    parts = []
    while i < len(tokens):
        parts.append(tokens[i])
        if ']' in tokens[i]:
            return ''.join(parts), i + 1
        i += 1
    return None, i


def _parse_var_tokens(body, scope_path):
    """Parse the token body of a $var declaration (the tokens between '$var'
    and '$end').

    Returns (sym, name, width, bit_str, scope_path, vtype), or None for a
    malformed declaration that should be skipped. Raises _VCDResourceError for
    hostile widths. Shared by both the one-line header fast path and the
    generic multi-line token parser so var interpretation is defined once.
    """
    if len(body) < 4:
        return None
    nbody = len(body)

    # Fast path for the two overwhelmingly common shapes emitted by VCS,
    # Verilator, Icarus, etc., where the size is a plain integer (not a split
    # '[ msb : lsb ]') and the reference is at most one trailing '[..]' token:
    #   4 tokens: vtype width sym name                  (scalar / packed bus)
    #   5 tokens: vtype width sym name [range-or-bit]   (bus or bit-select)
    # This avoids the two _collect_bracket_tokens scans per variable on files
    # that declare hundreds of thousands of them. Any shape that does not match
    # (bracketed size, split range, extra tokens) falls through to the general
    # parser below, so behaviour is unchanged for those.
    if nbody <= 5:
        b1 = body[1]
        if not b1.startswith('['):
            w = _safe_int_digits(b1)
            if w is not None:
                if w <= 0 or w > MAX_SIGNAL_WIDTH:
                    raise _VCDResourceError(
                        '$var width {} exceeds max {}; '
                        'file may be corrupt or malicious'.format(w, MAX_SIGNAL_WIDTH))
                vtype = body[0]
                sym = body[2]
                name = body[3]
                if nbody == 4:
                    return sym, name, w, None, scope_path, vtype
                # nbody == 5: trailing reference token body[4].
                ref = body[4]
                if ref.startswith('[') and ref.endswith(']'):
                    if w > 1:
                        # Range folded into displayed name ('data[7:0]').
                        return sym, name + ref, w, None, scope_path, vtype
                    # 1-bit [N]: keep as bit_str for the bit-explosion heuristic.
                    return sym, name, w, ref, scope_path, vtype
                # Unexpected 5th token (e.g. split '[7 :'); fall through.

    vtype = body[0]
    size_expr, idx_after_size = _collect_bracket_tokens(body, 1)
    if size_expr is not None:
        m = _HEADER_RANGE_RE.match(size_expr)
        if not m:
            return None
        msb = _safe_int_digits(m.group(1))
        lsb = _safe_int_digits(m.group(2))
        if msb is None or lsb is None:
            return None
        w = abs(msb - lsb) + 1
        idx = idx_after_size
    else:
        w = _safe_int_digits(body[1])
        if w is None:
            return None
        idx = 2
    # Refuse pathological widths before they reach fmt_val (which would try to
    # allocate pad bytes proportional to width). Real signals never approach
    # MAX_SIGNAL_WIDTH.
    if w <= 0 or w > MAX_SIGNAL_WIDTH:
        raise _VCDResourceError(
            '$var width {} exceeds max {}; '
            'file may be corrupt or malicious'.format(w, MAX_SIGNAL_WIDTH))
    if len(body) <= idx + 1:
        return None
    sym, name = body[idx], body[idx + 1]
    # A bracket after the name is a bit/range reference, possibly split across
    # tokens. For multi-bit refs with a range, fold it into the displayed name
    # ('data[7:0]'); for a 1-bit ref with [N], keep bit_str for the
    # bit-explosion heuristic.
    bit_str, _idx_after_ref = _collect_bracket_tokens(body, idx + 2)
    if bit_str is not None and w > 1:
        name = name + bit_str
        bit_str = None
    return sym, name, w, bit_str, scope_path, vtype


# Simulation keywords that wrap value_changes until $end. The keyword and $end
# are pure markers — the wrapped value_changes are parsed normally.
# Four-state VCD (18.2.3.9-12) + extended VCD (18.4.1 BNF).
_SIM_KEYWORDS = {'$dumpall', '$dumpoff', '$dumpon', '$dumpvars',
                 '$dumpports', '$dumpportsoff', '$dumpportson', '$dumpportsall'}

# Sections that can appear in the data area whose body is NOT value_changes
# and must be skipped wholesale until $end. $comment (18.2.3.1) is in both
# header and data; $vcdclose (18.3.6.1) wraps a final simulation time token.
_DATA_SKIP_SECTIONS = {'$comment', '$vcdclose'}

# ASCII whitespace byte values — the exact set bytes.split() (no separator)
# breaks on. Used by the t_max tail scan to find token boundaries when
# stitching a token split across a fixed-size read.
_ASCII_WS_BYTES = frozenset(b' \t\n\r\f\v')


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
        self._bit_map = {}          # sym -> list of (sig_id, bit_index)
        self._bit_state_template = {}  # sig_id -> initial bit list for replay-local reassembly
        self._parse_header()

    def _parse_header(self):
        """Parse VCD declarations and record where value changes begin.

        Common generated VCDs put one complete declaration per physical line
        ('$var wire 1 ! clk $end'). Those lines are handled by a direct fast
        path that avoids the per-token state machine; VCS/Verdi/GTKWave files
        can carry hundreds of thousands of $var records, so this materially
        cuts startup time for every command. Free-format lines fall through to
        the tolerant token parser: multi-line declarations, and — because VCD is
        free-format — several declarations packed onto one physical line
        ('$var .. $end $var .. $end', or two $scope). The fast path is taken only
        when the line holds exactly one self-contained declaration (a single
        trailing $end); both paths feed the same _parse_var_tokens helper, so the
        parsed signal table is identical regardless of which path a line takes
        (asserted by the header-equivalence tests, including multi-declaration
        and indented lines)."""
        scope = []
        scope_path = ''
        raw_vars = []  # (sym, name, width, bit_idx_str, scope_path, vtype)
        current_kw = None
        body = []
        done = False
        append_raw = raw_vars.append

        def _append_var(body_tokens):
            if len(raw_vars) >= MAX_VARS:
                raise _VCDResourceError(
                    'too many $var declarations: more than {}. '
                    'Set VCD_ANALYZER_MAX_VARS to raise the limit.'.format(MAX_VARS))
            rec = _parse_var_tokens(body_tokens, scope_path)
            if rec is not None:
                append_raw(rec)

        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            while not done:
                line = f.readline()
                if not line:
                    break

                # Fast path: one complete declaration on this line, with $end
                # on the same line, and we are not mid-section. Anything that
                # does not fit falls through to the generic token parser, so
                # correctness never depends on the fast path matching.
                if current_kw is None:
                    stripped = line.strip()
                    if stripped:
                        toks = stripped.split()
                        # Valid ONLY for a single self-contained declaration:
                        # exactly one $end, as the final token. A free-format
                        # line may legally pack several declarations
                        # ('$var .. $end $var .. $end', two $scope); those carry
                        # an interior $end and MUST fall through to the token
                        # parser below, which handles repeated keyword..$end
                        # groups. Gating on a single trailing $end is what keeps
                        # the fast and generic paths' signal tables identical.
                        single = toks[-1] == '$end' and toks.count('$end') == 1
                        if single and stripped.startswith('$var '):
                            if len(toks) >= 6:
                                _append_var(toks[1:-1])
                                continue
                        elif single and stripped.startswith('$scope '):
                            if len(toks) >= 4:
                                if len(scope) >= MAX_SCOPE_DEPTH:
                                    raise _VCDResourceError(
                                        '$scope nesting depth exceeds {}; '
                                        'file may be corrupt or malicious'.format(MAX_SCOPE_DEPTH))
                                scope.append(toks[2])
                                scope_path = '.'.join(scope)
                                continue
                        elif single and stripped == '$upscope $end':
                            if scope:
                                scope.pop()
                                scope_path = '.'.join(scope)
                            continue
                        elif single and stripped.startswith('$timescale '):
                            ts_body = ' '.join(toks[1:-1])
                            self.ts_str = '$timescale ' + ts_body + ' $end'
                            self.ts_sec = _parse_timescale(ts_body)
                            continue
                        elif single and (stripped.startswith('$date ') or
                                         stripped.startswith('$version ') or
                                         stripped.startswith('$comment ')):
                            kw = toks[0]
                            text = ' '.join(toks[1:-1])
                            if kw == '$date':
                                self.date = text
                            elif kw == '$version':
                                self.version = text
                            elif len(self.comments) < MAX_COMMENTS:
                                self.comments.append(text)
                            continue
                        # $enddefinitions is intentionally NOT fast-pathed:
                        # data tokens may share its line and the generic loop
                        # below already buffers them into _initial_tokens with
                        # the correct fail-fast cap.

                for tok in line.split():
                    if done:
                        # Buffer tokens that share the same line as
                        # `$enddefinitions $end`. These are data tokens
                        # (value_changes, timestamps), so they MUST NOT
                        # be silently dropped — that would corrupt the
                        # waveform without the user noticing. Fail-fast.
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
                            scope_path = '.'.join(scope)
                        elif current_kw == '$upscope':
                            if scope:
                                scope.pop()
                                scope_path = '.'.join(scope)
                        elif current_kw == '$var':
                            _append_var(body)
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
                            # comments are metadata, not data.
                            if len(self.comments) < MAX_COMMENTS:
                                self.comments.append(' '.join(body))
                        current_kw = None
                    else:
                        # Bound section body. In practice this only
                        # truncates oversized $comment / $date / $version
                        # bodies — metadata. $var bodies are 4-8 tokens,
                        # $scope is 2, $timescale is 2; none come close
                        # to the cap.
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

        # Precomputed signal "kind" — the single source of truth for the
        # event/state layering. Building these once here removes the per-event
        # signals.get(sid)['type'] lookup that _iter_changes' no-op bypass used
        # to pay on the value-change hot path, and lets the transition stream
        # carry a first-class kind so consumers (summary/search) no longer
        # re-derive type == 'event' themselves.
        #   _event_sids: sids whose declared var_type is 'event' (markers, not
        #     levels) — event triggers bypass no-op coalescing; each one counts.
        #   _sid_kind:   sid -> {'event','real','vector','scalar'}, from declared
        #     type + width (synthesized bit-buses are vectors).
        self._event_sids = frozenset(
            sid for sid, _info in self.signals.items()
            if _info.get('type') == 'event')
        self._sid_kind = {}
        for _sid, _info in self.signals.items():
            _vt = _info.get('type')
            if _vt == 'event':
                self._sid_kind[_sid] = 'event'
            elif _vt in ('real', 'realtime'):
                self._sid_kind[_sid] = 'real'
            elif _info.get('width', 1) > 1 or _info.get('synthesized'):
                self._sid_kind[_sid] = 'vector'
            else:
                self._sid_kind[_sid] = 'scalar'

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

    def _data_token_lists(self, chunk_size=None):
        """Yield successive non-empty token batches from the data section.

        The buffered initial tokens (those that trailed ``$enddefinitions`` on
        the same read) are yielded first. The data section is then read in
        large chunks and split in C, rather than iterated line by line: an
        FST-to-VCD converter can emit tens of millions of one-token lines, and
        per-line Python iteration dominates tokenizer time on those. A carry
        buffer holds any partial token spanning a chunk boundary, so the flat
        token stream is byte-for-byte identical to line-based ``.split()`` —
        verified exhaustively against the line-based reference across chunk
        sizes and adversarial whitespace.

        ``chunk_size`` overrides the read size. iter_events() uses the default
        (large, env-tunable) chunk; scan_time_range()'s t_min passes a small
        chunk and consumes lazily (it stops at the first ``#T``), so it never
        reads more than the head it needs.
        """
        if self._initial_tokens:
            yield list(self._initial_tokens)

        if chunk_size is None:
            chunk_size = _env_int('VCD_ANALYZER_TOKEN_CHUNK_SIZE', 4 * 1024 * 1024)
        if chunk_size < 65536:
            chunk_size = 65536
        carry = ''
        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(self._data_offset)
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if carry:
                    chunk = carry + chunk
                    carry = ''
                # If the chunk does not end on whitespace its final token may be
                # truncated. Cut at the last whitespace, tokenize the complete
                # prefix, and carry the remainder. rfind over the six VCD
                # whitespace chars stays in C (no per-character Python scan).
                if not chunk[-1].isspace():
                    cut = max(chunk.rfind(' '), chunk.rfind('\n'), chunk.rfind('\t'),
                              chunk.rfind('\r'), chunk.rfind('\v'), chunk.rfind('\f'))
                    if cut < 0:
                        carry = chunk
                        continue
                    carry = chunk[cut + 1:]
                    chunk = chunk[:cut]
                toks = chunk.split()
                if toks:
                    yield toks
        if carry:
            tail = carry.split()
            if tail:
                yield tail

    def _is_structural_token(self, tok):
        """Return True when tok is structural rather than an identifier_code.

        Only #<digits> has positional ambiguity: it can be a timestamp at
        top level, or a legal identifier_code after b/r/p. If such a token is
        declared as a normal signal or bit-exploded bit, it is the symbol;
        otherwise it is structural and must be pushed back so the outer loop
        can process it as a timestamp.
        """
        if tok is None:
            return True
        if tok.startswith('#') and len(tok) > 1 and tok[1].isdigit():
            return tok not in self.signals and tok not in self._bit_map
        return False

    def _consume_value_change(self, tok, next_token, pushback):
        """Parse one VCD value_change token sequence.

        Returns (identifier_code, value_str) on a valid value_change, or None
        when tok is malformed / not a value_change. This is the single shared
        validation path used by iter_events() and scan_time_range(), so info's
        reported time range stays aligned with dump/search parsing behavior.

        next_token is a zero-arg function over the same pushback-capable token
        stream as the caller. If a token consumed while validating b/r/p turns
        out to be structural, it is pushed back in the same order used by the
        old local parsers.
        """
        if not tok:
            return None
        first = tok[0]

        if first in '01xXzZ':
            sym = tok[1:]
            if not sym:
                return None
            return sym, first.lower()

        if first in 'bB':
            bits = tok[1:]
            # Consume the identifier_code BEFORE validating the value. A b-token
            # opener always owns the next token as its identifier (unless that
            # token is structural — a timestamp — which is pushed back).
            # Validating first and returning without consuming would leak a
            # malformed value's identifier back to the top level, where e.g.
            # 'b1012 1&' re-parses '1&' as a scalar change on signal '&' — a
            # phantom event. See test_freeformat.py (B4).
            sym = next_token()
            if self._is_structural_token(sym):
                if sym is not None:
                    pushback.append(sym)
                return None
            if not bits or bits.translate(_DEL_4STATE_CI):
                return None
            return sym, bits.lower()

        if first in 'rR':
            body = tok[1:]
            # Consume the identifier_code before validating (see the b-token
            # note above): 'rnan x!' must not leak 'x!' back to be mis-read as a
            # scalar change. Non-finite %g output (inf/nan) is a legal
            # real_number and is kept; see _REAL_NONFINITE_RE.
            sym = next_token()
            if self._is_structural_token(sym):
                if sym is not None:
                    pushback.append(sym)
                return None
            if len(body) > _REAL_MAX_LEN or not (
                    _REAL_RE.match(body) or _REAL_NONFINITE_RE.match(body)):
                return None
            return sym, body

        if first == 'p':
            # Extended VCD (18.4.3.1): p<state> <s0> <s1> <id>.
            # Keep this validation in one place so malformed port events are
            # treated identically by iter_events() and scan_time_range().
            state = tok[1:] if len(tok) > 1 else ''
            if not state or any(c not in _PORT_STATE for c in state):
                return None

            s0 = next_token()
            if s0 is None or len(s0) != 1 or s0 not in '01234567':
                if s0 is not None:
                    pushback.append(s0)
                return None

            s1 = next_token()
            if s1 is None or len(s1) != 1 or s1 not in '01234567':
                if s1 is not None:
                    pushback.append(s1)
                pushback.append(s0)
                return None

            sym = next_token()
            if self._is_structural_token(sym):
                if sym is not None:
                    pushback.append(sym)
                pushback.append(s1)
                pushback.append(s0)
                return None
            return sym, ''.join(_PORT_STATE[c] for c in state)

        return None

    def _scan_timestamps(self, token_lists, stop_at_first=False, resync=False):
        """Replay iter_events()'s top-level grammar over token_lists, ignoring
        the values themselves, to extract timestamps for scan_time_range().

        Returns ``(first_ts, saw_value_before_first_ts, last_ts)`` with each
        ``#T`` parsed by the hardened ``_parse_vcd_timestamp_token``. This is
        the single forward scanner shared by both ends of scan_time_range(),
        finally making _consume_value_change()'s "shared with scan_time_range()"
        contract true: info's time range is derived by exactly the rules
        iter_events() parses with —

          * ``$end`` and ``_SIM_KEYWORDS`` ($dumpvars/$dumpall/...) are
            top-level markers; any other ``$section`` ($comment/$vcdclose/
            unknown) has its body drained to the matching ``$end``;
          * a top-level ``#<digits>`` is ALWAYS a timestamp (no
            ``_is_structural_token`` gate at top level — matching iter_events);
          * ``b``/``r``/``p`` value changes go through _consume_value_change(),
            so a ``#<digits>`` that is a *declared identifier_code operand* is
            consumed rather than miscounted, and a pushed-back structural
            operand is re-read at top level exactly as the parser does.

        ``stop_at_first`` returns at the first top-level ``#T`` (t_min, which
        feeds tokens from ``_data_offset`` — a real top-level sync point).

        ``resync`` (t_max tail windows only): the window may begin inside a
        section body. Assume top level, but if a bare ``$end`` is met before any
        ``$X`` opener has confirmed the sync, the window began inside a drained
        section ($comment/$vcdclose) — discard the timestamps mis-read so far
        and resume at top level after that ``$end``. Since t_max scans the whole
        window and a trailing section's own ``$end`` is always inside an
        EOF-anchored window, a section-body ``#<digits>`` can never survive as
        the reported t_max.
        """
        pushback = []
        it = iter(token_lists)
        toks = ()
        ntoks = 0
        ti = 0

        def _next():
            nonlocal toks, ntoks, ti
            if pushback:
                return pushback.pop()
            while ti >= ntoks:
                nl = next(it, None)
                if nl is None:
                    return None
                toks = nl
                ntoks = len(nl)
                ti = 0
            tok = toks[ti]
            ti += 1
            return tok

        first_ts = None
        last_ts = None
        saw_value = False
        skipping = False        # inside a drained $comment/$vcdclose/unknown body
        synced = not resync     # top-level sync confirmed (no pending resync)

        while True:
            tok = _next()
            if tok is None:
                break
            if skipping:
                if tok == '$end':
                    skipping = False
                continue
            c0 = tok[0]
            if c0 == '$':
                if tok == '$end':
                    if not synced:
                        # Stray $end before any opener: the window began inside a
                        # section body — drop what we mis-read and resync.
                        first_ts = last_ts = None
                        saw_value = False
                        synced = True
                    continue
                # Any other '$X' is a real top-level structural marker.
                synced = True
                if tok in _SIM_KEYWORDS:
                    continue
                skipping = True     # $comment/$vcdclose/unknown -> drain to $end
                continue
            if c0 == '#' and len(tok) > 1 and tok[1].isdigit():
                v = _parse_vcd_timestamp_token(tok)
                if v is None:
                    continue        # malformed (e.g. '#1.5'); tolerate
                if first_ts is None:
                    first_ts = v
                last_ts = v
                if stop_at_first:
                    return first_ts, saw_value, last_ts
                continue
            # ---- value change (the value itself is irrelevant here) ----
            if c0 in '01xXzZ' and len(tok) > 1:
                saw_value = True
            elif c0 in 'bBrRp':
                if self._consume_value_change(tok, _next, pushback) is not None:
                    saw_value = True
            # else: stray token (bare '#', 'b', ...) — ignore
        return first_ts, saw_value, last_ts

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

        Multiple value_changes per timestamp are emitted: the IEEE 1364
        grammar allows any number of value_changes per simulation_time, and a
        writer may legally emit several for the same identifier within one
        timestamp (delta-cycle style dumps). A record that merely re-asserts a
        signal's current value is a no-op and adds no event: consecutive
        identical records for a signal coalesce (a '1a 1a' pair is one event),
        and the previously observed value is tracked across timestamp
        boundaries so a $dumpall/$dumpon checkpoint re-emitting the current
        value stays a no-op (the 1.3.19 static/active accounting is preserved). Event variables are
        markers, not levels: every record counts ('VCD event variables count
        each trigger'). Snapshot/compare last-write-wins semantics are
        unchanged.
        """
        for time, sid, _prev, val in self._iter_changes(t0, t1, sids):
            yield time, sid, val

    def iter_transitions(self, t0=0, t1=None, sids=None):
        """Per-signal transition stream: yield (time, sid, prev, value, kind).

        Same ordering and no-op/event semantics as iter_events, but each event
        also carries the previously observed value (prev; None on first
        observation) and the precomputed signal kind ('event'/'real'/'vector'/
        'scalar'), so consumers (summary, search) need not track prior state or
        re-derive type themselves. This is the TRANSITIONS view of the change
        stream.
        """
        sid_kind = self._sid_kind
        for time, sid, prev, val in self._iter_changes(t0, t1, sids):
            yield time, sid, prev, val, sid_kind[sid]

    def _iter_changes(self, t0=0, t1=None, sids=None):
        """Core change stream: yield (time, sid, prev, value) per value_change.

        Single semantic core behind iter_events (drops prev),
        iter_transitions (adds kind) and the state_* folds. Owns no-op
        coalescing, cross-timestamp last_val persistence, event-variable
        trigger counting, bit-exploded bus assembly, the t0 catch-up and
        the sids laziness. See iter_events for the value-change fidelity
        contract; prev is the value seen before this change (None on first
        observation).
        """
        cur_t = 0
        pending = []       # ordered [(sid, val), ...] — preserves intra-timestamp order
        last_val = {}      # sid -> previously observed value (no-op suppression)

        def _record(sid, val):
            # Append unless this is a no-op re-assertion of the previously
            # observed value. Event variables skip the check: their records
            # are trigger markers and each one counts. prev (the value seen
            # before this change, or None on first observation) rides along
            # so the transition view need not recompute it.
            prev = last_val.get(sid)
            if sid not in self._event_sids and prev == val:
                return
            pending.append((sid, prev, val))
            last_val[sid] = val

        def _flush():
            if not pending:
                return []
            items = list(pending)
            pending.clear()
            # last_val is deliberately NOT cleared: it is the running
            # "previously observed value" used to suppress no-op re-emissions
            # across timestamp boundaries (e.g. $dumpall checkpoints).
            return items

        # Flattened tokenizer. The data section is consumed as a sequence of
        # per-line token *lists* (self._data_token_lists); the main loop reads
        # the current list by index, so only line boundaries pay a next() call
        # — the per-token generator resume that dominated tokenizer time on
        # large files is gone. Pushback is honored on every read, so the b/r/p
        # look-ahead and $-section skipping keep their exact prior semantics.
        list_iter = self._data_token_lists()
        pushback = []
        toks = ()
        ntoks = 0
        ti = 0
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
            nonlocal toks, ntoks, ti
            if pushback:
                return pushback.pop()
            while ti >= ntoks:
                nl = next(list_iter, None)
                if nl is None:
                    return None
                toks = nl
                ntoks = len(nl)
                ti = 0
            tok = toks[ti]
            ti += 1
            return tok

        try:
            while True:
                # Inline token fetch (hot path): a direct index read with no
                # function call for the common case; _next() is reserved for
                # the parser's b/r/p look-ahead and section skipping.
                if pushback:
                    tok = pushback.pop()
                elif ti < ntoks:
                    tok = toks[ti]
                    ti += 1
                else:
                    nl = next(list_iter, None)
                    if nl is None:
                        break
                    toks = nl
                    ntoks = len(nl)
                    tok = toks[0]
                    ti = 1

                c0 = tok[0]
                # Top-level $keyword. Known wrappers ($dumpvars etc) and a bare
                # $end are pass-through markers; any other $section's body is
                # dropped to its $end so '$bogus 1! $end' can't pollute the
                # waveform. Gating on the first character keeps non-$ tokens
                # (the overwhelming majority) out of these comparisons.
                if c0 == '$':
                    if tok == '$end' or tok in _SIM_KEYWORDS:
                        continue
                    while True:
                        t = _next()
                        if t is None or t == '$end':
                            break
                    continue

                if c0 == '#' and len(tok) > 1 and tok[1].isdigit():
                    new_t = _parse_vcd_timestamp_token(tok)
                    if new_t is None:
                        # Malformed (e.g. '#1.5'); silently skip per round-7 policy.
                        continue
                    if cur_t >= t0:
                        for sid, prev, val in _flush():
                            yield cur_t, sid, prev, val
                    cur_t = new_t
                    if t1 is not None and cur_t > t1:
                        return
                    continue

                # ---- Value change ----
                # The 1-bit scalar form (a single leading 0/1/x/z/X/Z followed
                # by the identifier_code) is by far the most common token, so it
                # is parsed inline here without a helper call. b/r/p forms keep
                # going through _consume_value_change so the malformed-token
                # validation rules live in exactly one place.
                if c0 in '01xXzZ' and len(tok) > 1:
                    sym = tok[1:]
                    # Fast-path filter: drop unneeded signals before any work.
                    if sids is not None and sym not in sids and sym not in bit_map:
                        continue
                    val = c0 if c0 in '01xz' else c0.lower()
                elif c0 in 'bBrRp':
                    # Fast-path filter peek for b/r (identifier is the next
                    # token). p is left to the standalone-stage filter, matching
                    # prior behavior.
                    if sids is not None and c0 in 'bBrR':
                        sym_tok = _next()
                        if sym_tok is not None and not self._is_structural_token(sym_tok):
                            if sym_tok not in sids and sym_tok not in bit_map:
                                continue  # consume both tokens, skip
                            pushback.append(sym_tok)  # needed — put back for parser
                        elif sym_tok is not None:
                            pushback.append(sym_tok)
                    parsed = self._consume_value_change(tok, _next, pushback)
                    if parsed is None:
                        continue
                    sym, val = parsed
                else:
                    # Not a value_change opener (e.g. stray '#', bare 'b').
                    continue

                # Catch-up before t0: update bit_state only, don't emit.
                # Standalone state is owned by callers (e.g. state_at
                # accumulates it from yielded events), so nothing to do here
                # for the standalone case — the continue is correct.
                if cur_t < t0:
                    if sym in bit_map:
                        bit_val = val if len(val) == 1 and _is_4state_bits(val) else 'x'
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
                    bit_val = val if len(val) == 1 and _is_4state_bits(val) else 'x'
                    for gid, idx in bit_map[sym]:
                        bit_state[gid][idx] = bit_val
                        if sids is None or gid in sids:
                            _record(gid, ''.join(reversed(bit_state[gid])))

                # Standalone signal (may run after the bit-bus branch above when
                # the sym serves both roles).
                info = self.signals.get(sym)
                if info is None:
                    continue
                if sids is not None and sym not in sids:
                    continue
                # Inline the over-wide clamp guard. A scalar value (len 1) can
                # never exceed a declared width >= 1, and on real dumps ~93% of
                # standalone values are scalars and over-wide values are absent
                # entirely — so calling _clamp_overwide_logic_value() for every
                # event is almost pure call/dict/len overhead across tens of
                # millions of events. Take the function only when the value is
                # actually long enough to possibly need clamping; the helper
                # remains the single source of truth for that rare case.
                if len(val) == 1:
                    _record(sym, val)
                else:
                    w = info.get('width')
                    if w is None or len(val) <= w:
                        _record(sym, val)
                    else:
                        _record(sym, _clamp_overwide_logic_value(val, info))

            # Final flush
            if cur_t >= t0:
                for sid, prev, val in _flush():
                    yield cur_t, sid, prev, val
        finally:
            close = getattr(list_iter, 'close', None)
            if close is not None:
                close()

    def scan_time_range(self):
        """Min/max timestamps in the file.

        Both ends are found by a single FORWARD scanner, ``_scan_timestamps``,
        which replays iter_events()'s top-level grammar (see that method), so
        info's time range is derived by exactly the parser's rules:

        - **t_min**: forward scan from ``_data_offset`` — a real top-level sync
          point — stopping at the first top-level ``#T`` (typically within the
          first few KB). Value changes, or a ``$dumpvars`` block, before any
          ``#T`` yield t_min = 0.
        - **t_max**: the same forward scanner over a *small tail window* read
          from EOF, grown geometrically until a top-level ``#T`` is found. The
          last ``#T`` in file order is the last timestamp — matching
          iter_events()'s final ``cur_t`` (which ``_search_end_time`` relies on
          as the implicit search end). A legal VCD may carry an unbounded
          value_change run, or a large ``$dumpall`` checkpoint, after the final
          ``#T``; grow-on-miss covers that. A window that begins inside a
          section body is handled by the scanner's resync, and the final grow
          reaches the data-section floor — a provably-correct full forward scan
          that the old reverse walk never had.

        Reading only a bounded tail (``VCD_ANALYZER_TAIL_WINDOW``, default
        64 KiB, doubled on a miss) keeps ``info`` on a 500 MB VCD to well under
        a second instead of the ~90 s a full sequential scan would cost. All
        ``#T`` parsing routes through the hardened ``_parse_vcd_timestamp_token``
        (bounded digits, int64 cap), so a hostile timestamp yields a clean CLI
        error rather than a raw traceback.

        (Replaces a reverse tail walk that reconstructed VCD grammar backwards
        from an arbitrary offset — a recurring source of correctness bugs. The
        forward scanner is provably equal to the event stream; see
        ``_scan_timestamps``. ``_DATA_SKIP_SECTIONS`` stays documentation-only:
        the "any ``$X`` that is not ``$end``/``$dump*``" drain rule matches
        iter_events() exactly.)
        """
        # -- t_min: forward scan from the data-section start, stop at first #T --
        # Small lazy chunks (not iter_events' large read): _scan_timestamps
        # returns at the first top-level #T, so only the head is read. close()
        # releases the generator's file handle once we stop pulling from it.
        head = self._data_token_lists(chunk_size=64 * 1024)
        try:
            first_ts, saw_value, _ = self._scan_timestamps(head, stop_at_first=True)
        finally:
            head.close()
        t_min = 0 if saw_value else first_ts

        # -- t_max: forward scan over a bounded EOF tail window, grow on miss --
        # Forward scanning (not reverse grammar reconstruction) gives exact
        # parity with iter_events(). The small initial window keeps the common
        # case — the last #T sits a few KB before EOF — cheap; grow-on-miss
        # covers a large trailing value_change run or $dumpall checkpoint. Each
        # grow re-reads a strictly larger EOF window and rescans from scratch,
        # so no cross-window carry/skip state is needed.
        file_size = os.path.getsize(self.path)
        # _data_offset may be a text-mode tell() cookie (opaque, possibly larger
        # than file_size); clamp to a safe floor for the binary tail read.
        floor = self._data_offset if self._data_offset < file_size else 0
        window = _env_int('VCD_ANALYZER_TAIL_WINDOW', 64 * 1024)
        if window < 1:
            window = 1
        t_max = None
        while t_max is None:
            start = max(floor, file_size - window)
            with open(self.path, 'rb') as f:
                f.seek(start)
                data = f.read(file_size - start)
            if start > floor:
                # The low edge may cut a token; drop the leading partial
                # fragment. Safe: if it held the only #T this window "misses"
                # and the next (larger) window re-reads it intact.
                j = 0
                n = len(data)
                while j < n and data[j] not in _ASCII_WS_BYTES:
                    j += 1
                data = data[j:]
            toks = data.decode('ascii', errors='replace').split()
            _, _, last = self._scan_timestamps([toks], resync=(start > floor))
            if last is not None:
                t_max = last
                break
            if start <= floor:
                break            # whole data section scanned: no top-level #T
            window *= 2          # grow-on-miss
        if t_max is None:
            t_max = t_min
        if t_min is None:
            t_min = t_max
        return t_min, t_max

    def state_at(self, t_at, sids=None):
        """Settled signal state at t_at: {sig_id: value} for known signals.

        Last-write-wins fold of the change stream through t_at (inclusive).
        Only signals with an observed value appear; no unknowns are invented.
        This is the STATE@T view used by snapshot and as a baseline.
        """
        state = {}
        for _t, sid, val in self.iter_events(0, t_at, sids):
            state[sid] = val
        return state

    def state_before(self, t_at, sids=None):
        """Settled state strictly before t_at (exclusive).

        VCD timestamps are integer ticks, so the exclusive snapshot is the
        inclusive snapshot at t_at - 1; before t=0 there is no prior state.
        """
        if t_at <= 0:
            return {}
        return self.state_at(t_at - 1, sids)

    def state_pair(self, ta, tb, sids=None):
        """Settled state at ta and at tb in one pass (assumes ta <= tb).

        Returns (state_a, state_b), each {sig_id: value} = last value at or
        before the respective boundary (inclusive). Used by compare.
        """
        state = {}
        state_a = None
        for t, sid, val in self.iter_events(0, tb, sids):
            if state_a is None and t > ta:
                state_a = dict(state)
            state[sid] = val
        if state_a is None:
            state_a = dict(state)
        return state_a, dict(state)



# -- Subcommands -------------------------------------------------------------

_DEFAULT_LIMIT = 500


def _json(obj):
    """Compact JSON for agent use."""
    print(json.dumps(obj, ensure_ascii=False, separators=(',', ':')))


def _limit(args):
    """Resolve global output limit. --verbose disables truncation unless an
    explicit --limit was supplied. --limit 0 always means unlimited."""
    val = getattr(args, 'limit', None)
    if val is None:
        return 0 if getattr(args, 'verbose', False) else _DEFAULT_LIMIT
    if val < 0:
        raise _LimitParseError('limit must be non-negative; got {}'.format(val))
    return val


def _clip(seq, limit):
    if limit == 0:
        return seq, False
    return seq[:limit], len(seq) > limit


def _trunc_text(shown, total, noun, exact):
    """Clipped-result notice.

    Stands off by a blank line and leads with TRUNCATED, because the previous
    one-line '... truncated: 2/3 rows shown.' was easy to skim past — and it
    named neither of the flags that lift the cap.
    """
    return ('\n>> TRUNCATED: showing {} of {}{} {}. '
            'Raise the cap with --limit N, or --limit 0 for all.').format(
                shown, total, '' if exact else '+', noun)


def _trunc_line(shown, total, noun):
    return _trunc_text(shown, total, noun, True)


def _trunc_line_lower_bound(shown, total, noun):
    """Truncation line when scanning stopped at the first unshown result.

    Used by streaming commands where --limit is an execution bound, not just
    an output bound. `total` is a lower bound (normally shown + 1),
    not the exact global result count.
    """
    return _trunc_text(shown, total, noun, False)


def _trunc_hint(truncated, shown, total, exact, noun):
    """JSON `hint` field for a clipped result, and nothing for a complete one.

    `truncated: true` sitting among a dozen other keys is easy to skim past; a
    sentence naming the flag that lifts the cap is not. Appears only when
    something was clipped, so no existing key changed name, type, or meaning.
    """
    if not truncated:
        return {}
    return {'hint': 'showing {} of {}{} {}; raise the cap with --limit N, '
                    'or --limit 0 for all'.format(
                        shown, total, '' if exact else '+', noun)}


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


def _parse_target_value(text):
    """Parse search/condition target once with bounded cost.

    Returns (target_raw, target_int, target_real):

      - Numeric targets (decimal, 0x..., 0b..., b...) get target_int and are
        matched only by numeric equality.
      - 4-state binary literals with x/z keep a raw bit-string target. Explicit
        binary prefixes are stripped because VCD stores vector values as
        ``1x0`` internally, not ``b1x0``.
      - A bare number carrying a fraction or exponent (3.14, 1e-9) is a
        target_real, matched only against real/realtime signals.

    Invalid hex and negative decimal targets are rejected rather than silently
    producing no matches; VCD value_change text is unsigned, and x/z literals
    should be written in binary form (e.g. b1x0z).

    A bare target that is none of the above is REJECTED rather than kept as an
    opaque literal that could only ever compare unequal. The tool has no
    in-string boolean syntax, so `--condition "a=1 OR b=1"` parses as a single
    term whose target is the text `1 or b=1`; accepting it produced a
    plausible-looking "no match" instead of an error. OR is spelled by
    repeating --condition.
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
            return raw, int(raw, 16), None
        except ValueError:
            raise _ValueParseError(
                'invalid hex target {!r}; x/z literals must use binary form like b1x0z'.format(text))

    if raw.startswith('0b') or raw.startswith('b'):
        body = raw[2:] if raw.startswith('0b') else raw[1:]
        if not body:
            raise _ValueParseError('binary target must contain at least one bit')
        if len(body) > MAX_SIGNAL_WIDTH:
            raise _ValueParseError(
                'binary target too wide; max bits is {}'.format(MAX_SIGNAL_WIDTH))
        try:
            return body, int(body, 2), None
        except ValueError:
            if all(c in '01xz' for c in body):
                return body, None, None
            raise _ValueParseError(
                'invalid binary target {!r}; expected only 0/1/x/z'.format(text))

    # Bare target, in order: decimal integer, 4-state literal, real number.
    # Anything else is a parse error -- see the docstring on why an opaque
    # literal fallback is worse than saying so.
    if raw.startswith('+'):
        raise _ValueParseError(
            'signed target values are not supported; write unsigned values')
    if raw.isdigit():
        if len(raw) > MAX_DECIMAL_VALUE_DIGITS:
            raise _ValueParseError(
                'decimal target too long; max digits is {}'.format(MAX_DECIMAL_VALUE_DIGITS))
        return raw, int(raw), None
    if len(raw) > MAX_SIGNAL_WIDTH:
        raise _ValueParseError(
            'literal target too wide; max characters is {}'.format(MAX_SIGNAL_WIDTH))
    if _is_4state_bits(raw):
        return raw, None, None
    # A number carrying a fraction or an exponent targets a real/realtime
    # signal. nan/inf are rejected: a VCD real may legally be dumped as either,
    # but neither is a useful equality target (nan never compares equal).
    if len(raw) <= MAX_DECIMAL_VALUE_DIGITS + 32:
        try:
            fval = float(raw)
        except ValueError:
            fval = None
        if fval is not None and math.isfinite(fval):
            return raw, None, fval
    raise _ValueParseError(
        'invalid target {!r}; expected a decimal (5), hex (0xff), binary (b1010), '
        '4-state literal (1x0z), or real number (3.14). Note there is no in-string '
        'boolean syntax: repeat --condition to OR clauses'.format(text))


def _is_4state_bits(text):
    return bool(text) and not text.translate(_DEL_4STATE_LOWER)


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


def _real_target_number(target_int, target_real):
    """Numeric value of a target for real/realtime comparison, or None.

    A real target carries its float directly; a decimal/hex/binary target is
    an exact integer that is converted on demand, so `dac=100` asks the same
    question as `dac=100.0`. A bus-width integer can exceed the float range,
    which is not an error -- it simply cannot equal any finite real.
    """
    if target_real is not None:
        return target_real
    if target_int is not None:
        try:
            return float(target_int)
        except OverflowError:
            return None
    return None


def _value_matches(value, target_raw, target_int, width=None, kind=None,
                   target_real=None):
    """Match a recorded value against a parsed search target.

    The recorded value is classified by the signal's DECLARED kind, never by
    sniffing its characters. A real signal carries the simulator's %g text as
    its value, so a real 100.0 renders as "100"; read as a bit string that is
    binary 100 == 4, which made `dac=4` match spuriously and `dac=100` miss.

    kind 'real'/'realtime' therefore compares numerically as floats and never
    as bits. kind 'event' has no level at all and never matches (level terms
    on event variables are rejected at resolve time; this is the belt).

    For logic signals (kind 'vector'/'scalar', or None for callers that do not
    classify):

    - Numeric targets (decimal/hex/binary without x/z) match only by numeric
      equality, avoiding the decimal/binary collision where target 10 would
      otherwise raw-match a 2-bit value "10".
    - Non-numeric 4-state targets (for example b1x0 -> raw "1x0") match as bit
      patterns. If the signal width is known, both the dumped value and the
      target are left-extended to that width using VCD rules before
      comparison. This preserves exact x/z semantics while avoiding the need
      to write every leading zero for wide buses. Non-bit-string literals fall
      back to exact string equality.
    """
    if kind == 'event':
        return False
    if kind == 'real':
        target_num = _real_target_number(target_int, target_real)
        if target_num is None:
            return False
        try:
            return float(value) == target_num
        except (TypeError, ValueError):
            return False
    if target_real is not None:
        # A real-number target against a logic signal (rejected at resolve
        # time; this is the belt for direct callers).
        return False
    if target_int is not None:
        iv = val_to_int(value)
        return iv is not None and iv == target_int
    if width is not None and _is_4state_bits(value) and _is_4state_bits(target_raw):
        if len(target_raw) > width:
            return False
        return _left_extend_bits(value, width) == _left_extend_bits(target_raw, width)
    return value == target_raw


_COND_RE = re.compile(r'^\s*(.+?)\s*(==|=|!=)\s*(.+?)\s*$')


def _has_unknown(value, kind=None):
    """True when a VCD value is unknown/ambiguous for negative predicates.

    A real signal's value is decimal text, so a literal 'x'/'z' in it (as in
    the %g rendering of a hex-ish string, or 'nan') is not a 4-state unknown;
    only logic values can be unknown in that sense.
    """
    if value is None:
        return True
    if kind == 'real':
        return False
    return 'x' in value or 'z' in value


def _condition_match(value, op, target_raw, target_int, width=None, kind=None,
                     target_real=None):
    """Evaluate one resolved condition against a raw VCD value.

    Equality reuses the kind-aware value matcher, so real signals compare
    numerically, numeric targets on logic signals compare numerically, and
    mixed x/z literals compare as 4-state bit patterns, width-aware when the
    signal width is available.

    Inequality is deliberately stricter than `not _value_matches(...)`:
    x/z/undef do NOT satisfy `!=`. In RTL debug, unknown is not evidence that
    a signal is definitely different from a value. Users who want unknowns
    should ask for them explicitly, e.g. `valid=x`.
    """
    if value is None:
        return False
    if op in ('=', '=='):
        return _value_matches(value, target_raw, target_int, width, kind, target_real)
    if op == '!=':
        if _has_unknown(value, kind):
            return False
        return not _value_matches(value, target_raw, target_int, width, kind, target_real)
    raise AssertionError('unsupported condition operator {}'.format(op))


_CHANGED_PREFIX = 'changed('


def _parse_changed_term(item):
    """Recognize the `changed(SIG)` edge-predicate form.

    Any term starting with `changed(` (case-insensitive) is claimed by this
    syntax. A bare term with no operator was never valid before, so no working
    condition changes meaning; the one shadowed spelling is a level term on an
    escaped identifier that itself begins with `changed(`, which stays
    reachable through a scope-qualified pattern (`tb.changed(a)=1` does not
    start with the prefix).

    Returns None when the term does not start with the prefix; malformed
    `changed(...` shapes get targeted errors rather than the generic one.
    """
    if item[:len(_CHANGED_PREFIX)].lower() != _CHANGED_PREFIX:
        return None
    body = item[len(_CHANGED_PREFIX):]
    if body.endswith(')'):
        inner = body[:-1].strip()
        if not inner:
            raise _ConditionParseError(
                'changed() requires a signal, e.g. changed(req)')
        return {'kind': 'changed', 'pattern': inner, 'original': item}
    if ')' in body:
        # e.g. `changed(req)=1` -- trailing text after the closing paren.
        raise _ConditionParseError(
            'invalid term {!r}: changed(SIG) is a predicate and takes no comparison'.format(item))
    # No closing paren: a plain missing ')', or `changed(a,b)` cut apart by the
    # AND comma before this function ever saw it.
    raise _ConditionParseError(
        "invalid term {!r}: unclosed changed( -- missing ')'? note changed() takes "
        'exactly one signal: a comma inside the parens is read as an AND separator, '
        'so "both changed" is changed(a),changed(b)'.format(item))


def _parse_conditions(text):
    """Parse one comma-separated AND clause into unresolved condition dicts.

    A term is either a level comparison (`SIG=VAL`, `SIG==VAL`, `SIG!=VAL`) or
    the edge predicate `changed(SIG)`, which is true at exactly the ticks where
    SIG transitions. Each dict carries a 'kind' of 'level' or 'changed'.
    """
    if text is None or not str(text).strip():
        raise _ConditionParseError('search requires --condition')
    conditions = []
    for item in str(text).split(','):
        item = item.strip()
        if not item:
            continue
        changed = _parse_changed_term(item)
        if changed is not None:
            conditions.append(changed)
            continue
        m = _COND_RE.match(item)
        if not m:
            raise _ConditionParseError(
                'invalid condition {!r}; expected SIG=VAL, SIG==VAL, SIG!=VAL, '
                'or changed(SIG)'.format(item))
        sig_pat = m.group(1).strip()
        op = m.group(2)
        val_text = m.group(3).strip()
        if not sig_pat or not val_text:
            raise _ConditionParseError(
                'invalid empty signal/value in condition {!r}'.format(item))
        target_raw, target_int, target_real = _parse_target_value(val_text)
        conditions.append({
            'kind': 'level',
            'pattern': sig_pat,
            'op': op,
            'target_raw': target_raw,
            'target_int': target_int,
            'target_real': target_real,
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


def _term_key(c):
    """De-duplication key for one resolved term.

    Keyed on the resolved sid (so alias paths for one signal fold), the
    operator slot ('changed' for the edge predicate, which no comparison
    operator can spell), and the target value AS WRITTEN -- `5` and `0x5` are
    the same number but different spellings and deliberately do not fold, so
    there is no cross-base normalization to get wrong. Shared by the
    within-clause term de-dup and the cross-clause clause_key below, so the
    two can never drift apart.
    """
    if c['kind'] == 'changed':
        return (c['sid'], 'changed', '')
    return (c['sid'], c['op'], '{}:{}'.format(
        c['target_raw'], c['target_int'] is not None or c['target_real'] is not None))


def _check_term_kind(c):
    """Reject a level term the signal's declared kind cannot answer.

    Silence is the wrong answer here: an event variable has no level, and a
    real signal cannot equal a bit pattern, so leaving these to the matcher
    would produce a plausible-looking empty result instead of saying that the
    question does not apply to this signal.
    """
    kind = c['kind_of_signal']
    if kind == 'event':
        raise _ConditionParseError(
            "condition {!r} targets event variable {}, which has no level; "
            'use changed({}) to fire on each trigger'.format(
                c['original'], c['path'], c['path']))
    if kind == 'real':
        if c['target_int'] is None and c['target_real'] is None:
            raise _ConditionParseError(
                'condition {!r} compares real signal {} against a bit pattern; '
                'write a decimal or real number, e.g. {}=3.14'.format(
                    c['original'], c['path'], c['path']))
    elif c['target_real'] is not None:
        raise _ConditionParseError(
            'condition {!r} compares logic signal {} (width {}) against the real '
            'number {}; use a decimal, hex, binary, or 4-state target'.format(
                c['original'], c['path'], c['width'], c['value_text']))


def _resolve_conditions(vcd, text):
    """Parse and resolve one AND clause's signal patterns to signal ids."""
    resolved = []
    seen = set()
    for c in _parse_conditions(text):
        role = 'changed() signal' if c['kind'] == 'changed' else 'condition signal'
        sid = _resolve_one_signal(vcd, c['pattern'], role)
        c = dict(c)
        c['sid'] = sid
        c['path'] = vcd.signals[sid]['path']
        c['width'] = vcd.signals[sid]['width']
        # 1.4.0's precomputed kind table, which exists exactly so consumers
        # need not re-derive a signal's class from its declared type.
        c['kind_of_signal'] = vcd._sid_kind[sid]
        if c['kind'] == 'level':
            _check_term_kind(c)
        key = _term_key(c)
        if key in seen:
            continue
        seen.add(key)
        resolved.append(c)
    return resolved


def _resolve_clauses(vcd, texts):
    """Resolve every --condition into an OR clause list (OR-of-ANDs).

    Each --condition is one comma-separated AND clause; repeating the flag ORs
    the clauses. Duplicate clauses -- identical, term-order permuted, or
    alias-equivalent -- fold silently to the first occurrence, so a scripted
    caller that repeats a clause does not double the echoed condition. A single
    clause keeps exactly today's behavior, echo included.
    """
    if texts is None:
        raise _ConditionParseError('search requires --condition')
    if isinstance(texts, str):
        texts = [texts]
    clauses = []
    seen = set()
    for text in texts:
        clause = _resolve_conditions(vcd, text)
        key = tuple(sorted(_term_key(c) for c in clause))
        if key in seen:
            continue
        seen.add(key)
        clauses.append(clause)
    if not clauses:
        raise _ConditionParseError('search requires --condition')
    return clauses


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


def _conditions_hold(state, conditions, changed_sids=frozenset(),
                     ov_sid=None, ov_val=None):
    """Do all of one clause's AND terms hold?

    `state` maps sid to raw value; `changed_sids` is the set of signals that
    genuinely transitioned at the tick under evaluation (empty outside event
    mode, where no clause carries a changed() term).

    `ov_sid`/`ov_val` override one signal's value for this evaluation. Event
    mode uses it for the edge's own signal: everything else is read at the
    tick's settled state (so the answer does not depend on the order records
    happen to be written in), while the transitioning signal is read at the
    value it took AT that edge — which is what makes `changed(s),s=1` mean
    "rising edge of s" even when s toggles several times inside one tick.
    """
    for c in conditions:
        if c['kind'] == 'changed':
            if c['sid'] not in changed_sids:
                return False
            continue
        sid = c['sid']
        value = ov_val if sid == ov_sid else state.get(sid)
        if not _condition_match(
                value, c['op'], c['target_raw'],
                c['target_int'], c.get('width'), c.get('kind_of_signal'),
                c.get('target_real')):
            return False
    return True


def _any_clause_holds(state, clauses, changed_sids=frozenset()):
    """OR across clauses: the search holds when ANY clause's terms all hold.

    With a single clause this is exactly _conditions_hold, so single
    --condition behavior is unchanged.
    """
    for clause in clauses:
        if _conditions_hold(state, clause, changed_sids):
            return True
    return False


def _condition_label(conditions):
    return ','.join(c['original'] for c in conditions)


def _condition_result_text(conditions):
    return ','.join(
        'changed({})'.format(c['path']) if c['kind'] == 'changed'
        else '{}{}{}'.format(c['path'], c['op'], c['value_text'])
        for c in conditions)


def _join_clauses(clauses, render):
    """Echo the clause list: a lone clause as-is, several as `(..) OR (..)`.

    The single-clause form is deliberately unparenthesized so that every
    existing one-condition invocation echoes byte-for-byte as before.
    """
    if len(clauses) == 1:
        return render(clauses[0])
    return ' OR '.join('({})'.format(render(c)) for c in clauses)


def _show_values(vcd, state, show_sids, verbose=False, ov_sid=None, ov_val=None):
    """Return (values, meta) for show signals in current state.

    The return shape is intentionally stable regardless of verbose. meta is
    None unless verbose=True. This avoids type-dependent unpacking in search.

    `ov_sid`/`ov_val` override one signal, matching _conditions_hold: an event
    row shows the transitioning signal at the value it took at that edge, and
    every other shown signal at the tick's settled value.
    """
    values = {}
    meta = {} if verbose else None
    for sid in show_sids:
        info = vcd.signals[sid]
        path = info['path']
        raw = ov_val if sid == ov_sid else state.get(sid)
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


def _transition_groups(vcd, t0, t1, sids):
    """Yield (time, [(sid, prev, val, kind), ...]) groups in time order.

    _event_groups over the TRANSITIONS view: same per-timestamp grouping, but
    each record keeps the previously observed value and the signal kind, which
    is what lets event mode compute a tick's transition set (and so answer
    "did a and b change together?") without re-deriving either.
    """
    cur_t = None
    group = []
    for t, sid, prev, val, kind in vcd.iter_transitions(t0, t1, sids):
        if cur_t is None:
            cur_t = t
        if t != cur_t:
            yield cur_t, group
            cur_t, group = t, []
        group.append((sid, prev, val, kind))
    if cur_t is not None:
        yield cur_t, group


def _summary_rows(vcd, t0, t1, sids):
    """Return (rows, counts) for window summary.

    Baseline captures state up to init_boundary: t=0 when the window starts
    at 0 (so $dumpvars initialization is part of the baseline, not counted
    as changes), or t0-1 when the window starts later (so value_changes
    exactly at --begin are counted as in-window events, fixing the boundary
    black-hole where transitions at the window edge were silently dropped).

    Static means known in baseline and no value changes inside the window.
    Undefined means selected but not known in baseline and no value changes
    inside the window. No unknown values are invented.

    For 1-bit signals, rise/fall counts are reported for clean 0->1 and 1->0
    transitions only. x/z-related transitions still count as changes, but not
    as rises/falls.

    The distinct-value count (`unique`) is exact up to
    VCD_ANALYZER_MAX_UNIQUE_VALUES (default 65536, read per call like
    VCD_ANALYZER_TOKEN_CHUNK_SIZE); beyond the cap it is a lower bound, and
    the row says so: JSON `unique_is_exact: false` (the key appears only when
    capped), text `uniq=N+`. This bounds memory on e.g. a 32-bit counter over
    tens of millions of changes instead of keeping every value string alive.
    """
    selected = _selected_sids(vcd, sids)
    init_boundary = 0 if t0 == 0 else t0 - 1
    # Per-call env read so tests can shrink the cap via monkeypatch.setenv
    # without reloading the module.
    unique_cap = _env_int('VCD_ANALYZER_MAX_UNIQUE_VALUES', 65536)

    # Baseline: {sid: val} — cheap str overwrites, same as state_at.
    # Stats dicts are created only once per signal, not on every baseline event.
    baseline = {}
    stats = {}

    def _make_stats(info, init_val):
        is_scalar = info['width'] == 1
        return {
            'changes': 0, 'first_at': None, 'last_at': None,
            'initial': init_val, 'last': init_val,
            'unique': {init_val} if init_val is not None else set(),
            'unique_capped': False,
            'rise_count': 0 if is_scalar else None,
            'fall_count': 0 if is_scalar else None,
            'scalar': is_scalar,
        }

    for t, sid, prev, val, _kind in vcd.iter_transitions(0, t1, selected):
        if t <= init_boundary:
            baseline[sid] = val
            continue

        # First event in analysis window for this signal —
        # initialize stats from baseline snapshot (if any).
        if sid not in stats:
            init_val = baseline.pop(sid, None)
            stats[sid] = _make_stats(vcd.signals[sid], init_val)

        s = stats[sid]
        # Count genuine transitions only. prev (carried by the transition
        # stream) is the value observed just before this change; on the first
        # in-window event it equals the baseline value, so a $dumpall/$dumpon
        # checkpoint re-emitting the current value (prev == val) is not counted
        # and a never-changing signal stays static. Repeated event-variable
        # triggers at the same value are likewise not double-counted here — dump
        # and search --changed expose each trigger; summary counts genuine value
        # transitions.
        if val != prev:
            if s['scalar']:
                if prev == '0' and val == '1':
                    s['rise_count'] += 1
                elif prev == '1' and val == '0':
                    s['fall_count'] += 1
            s['changes'] += 1
            if s['first_at'] is None:
                s['first_at'] = t
            s['last_at'] = t
            s['last'] = val
            if val not in s['unique']:
                if len(s['unique']) < unique_cap:
                    s['unique'].add(val)
                else:
                    # At cap: the count stays a lower bound, flagged on the row.
                    s['unique_capped'] = True

    # Signals that were in baseline but had no in-window events (static).
    for sid, val in baseline.items():
        stats[sid] = _make_stats(vcd.signals[sid], val)

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
            if s['unique_capped']:
                row['unique_is_exact'] = False
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
    _limit(args)
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
        if r['time_min'] is None:
            print('Time      : (no data in file)')
        else:
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
    limit = _limit(args)
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
        _json({'total': len(entries), 'shown': len(shown), 'truncated': trunc,
               **_trunc_hint(trunc, len(shown), len(entries), True, 'signals'),
               'signals': shown})
    else:
        # Numerator and denominator are both alias-path counts: 'entries' holds
        # one row per alias of each matched signal, so the total must likewise
        # count aliases across all signals (not unique signals) — otherwise a
        # single signal with two aliases prints a nonsensical "Matched: 2/1".
        total_aliases = sum(len(info['aliases']) for info in vcd.signals.values())
        print('Matched: {}/{}'.format(len(entries), total_aliases))
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
    limit = _limit(args)
    verbose = getattr(args, 'verbose', False)
    # Many value_changes share one timestamp, so memoize the formatted time
    # across consecutive events. fmt_time() depends only on (t, ts), so this
    # stays output-identical while collapsing ~one fmt_time call per timestamp
    # instead of one per event.

    if args.json:
        # JSON output needs the full event list materialized for serialization.
        total = 0
        truncated = False
        events = []
        last_t = object()
        last_th = None
        for t, sid, val in vcd.iter_events(t0, t1, sids):
            total += 1
            if limit != 0 and len(events) >= limit:
                truncated = True
                break
            info = vcd.signals[sid]
            if t != last_t:
                last_t = t
                last_th = fmt_time(t, ts)
            e = {'time': t, 'time_ticks': t, 'time_h': last_th,
                 'path': info['path'], 'value': fmt_val(val, info)}
            if verbose:
                e['width'] = info['width']
                e['type'] = info.get('type', 'wire')
            events.append(e)
        obj = {'shown': len(events), 'truncated': truncated,
               **_trunc_hint(truncated, len(events), total, False, 'events'),
               'events': events}
        obj.update(_total_json_fields(total, truncated))
        _json(obj)
        return

    # Text output streams straight to stdout: no per-event dict is built, and
    # lines are flushed in batches rather than one print() per line. On a dump
    # of millions of events this removes the intermediate list and most of the
    # write-call overhead. The emitted bytes are identical to the prior
    # two-pass implementation.
    write = sys.stdout.write
    buf = []
    buf_append = buf.append
    shown = 0
    total = 0
    truncated = False
    # One memoized sentinel drives both the T= header and the formatted time:
    # last_t and cur always changed on the same events.
    cur = object()
    last_th = None
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        total += 1
        if limit != 0 and shown >= limit:
            truncated = True
            break
        info = vcd.signals[sid]
        if t != cur:
            cur = t
            last_th = fmt_time(t, ts)
            buf_append('T={}\n'.format(last_th))
        if verbose:
            buf_append('  {:<55} w={} {} = {}\n'.format(
                info['path'], info['width'], info.get('type', 'wire'), fmt_val(val, info)))
        else:
            buf_append('  {:<55} = {}\n'.format(info['path'], fmt_val(val, info)))
        shown += 1
        if len(buf) >= 8192:
            write(''.join(buf))
            buf.clear()
    if shown == 0:
        print('(no changes in range)')
        return
    if buf:
        write(''.join(buf))
    if truncated:
        print(_trunc_line_lower_bound(shown, total, 'events'))


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
    limit = _limit(args)
    shown, trunc = _clip(ordered, limit)
    begin_h = fmt_time(t0, ts)
    end_h = fmt_time(t1, ts) if t1 is not None else None
    if args.json:
        _json({'window': {'begin': begin_h, 'end': end_h,
                          'begin_ticks': t0, 'begin_h': begin_h,
                          'end_ticks': t1, 'end_h': end_h}, **counts,
               'shown': len(shown), 'truncated': trunc,
               **_trunc_hint(trunc, len(shown), len(ordered), True, 'rows'),
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
                uniq = str(r.get('unique', 0))
                if not r.get('unique_is_exact', True):
                    uniq += '+'
                print('  {:<45} w={} {} chg={}{} init={} last={} first@{} last@{} uniq={}'.format(
                    r['path'], r['_width'], r['_type'], r['changes'], edge, r['init'], r['last'],
                    r.get('first_at', '-'), r.get('last_at', '-'), uniq))
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
    state = vcd.state_at(t_at, selected)
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
    limit = _limit(args)
    shown, trunc = _clip(rows, limit)
    if args.json:
        _json({'at': fmt_time(t_at, ts), 'at_ticks': t_at, 'at_h': fmt_time(t_at, ts),
               'selected': len(selected), 'known': len(state),
               'undefined': len(undef), 'shown': len(shown), 'truncated': trunc,
               **_trunc_hint(trunc, len(shown), len(rows), True, 'signals'),
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
    sa, sb = vcd.state_pair(ta, tb, sids)
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
    limit = _limit(args)
    shown, trunc = _clip(diffs, limit)
    if args.json:
        _json({'t1': fmt_time(ta, ts), 't1_ticks': ta, 't1_h': fmt_time(ta, ts),
               't2': fmt_time(tb, ts), 't2_ticks': tb, 't2_h': fmt_time(tb, ts),
               'total': len(diffs), 'shown': len(shown), 'truncated': trunc,
               **_trunc_hint(trunc, len(shown), len(diffs), True, 'diffs'),
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
        if t1_raw is None:
            # No --end was given, so t1 is the file's last timestamp. A --begin
            # past it is an empty range, not an end-before-begin ordering error;
            # say so instead of blaming an --end the user never supplied.
            raise _TimeParseError(
                'begin time {} is after the last event at {}; nothing to search'.format(
                    fmt_time(t0, ts), fmt_time(t1, ts)))
        raise _TimeParseError('end time must be >= begin time')

    clauses = _resolve_clauses(vcd, args.condition)

    # Mode split: a clause carrying a changed() term describes ticks (event
    # mode); one without describes spans (interval/segment mode). The two row
    # shapes cannot merge, so mixing is a usage error rather than a silent
    # pick of one.
    with_changed = [cl for cl in clauses
                    if any(c['kind'] == 'changed' for c in cl)]
    if with_changed and len(with_changed) < len(clauses):
        raise _ConditionParseError(
            'cannot mix changed() and level-only --condition clauses: a changed() '
            'clause fires at ticks (event mode) while a level-only clause spans '
            'time (interval mode); give every clause a changed() term, or run two '
            'searches')
    event_mode = bool(with_changed)
    changed_sids = sorted(
        {c['sid'] for cl in clauses for c in cl if c['kind'] == 'changed'},
        key=lambda sid: vcd.signals[sid]['path'])

    show_sids = _resolve_show_sids(vcd, args.show)
    if event_mode and not show_sids:
        # Event mode with no --show: watch the changed() signals themselves.
        show_sids = list(changed_sids)

    # Cost scales with the distinct signals referenced, not the clause count.
    selected = set(c['sid'] for cl in clauses for c in cl)
    selected.update(show_sids)

    limit = _limit(args)
    verbose = getattr(args, 'verbose', False)
    cond_label = _join_clauses(clauses, _condition_label)
    cond_text = _join_clauses(clauses, _condition_result_text)

    if event_mode:
        # Event mode is a per-TICK query with per-RECORD emission.
        #
        # Per tick: collect the tick's genuine transitions, apply every record,
        # then judge the clauses. Every signal EXCEPT the one transitioning is
        # read at the tick's SETTLED state, which is what makes the answer
        # independent of the order records happen to be written in — IEEE 1364
        # fixes neither the order nor the count of value_changes within one
        # simulation_time, so a level term decided halfway through a tick was
        # reading an artifact of the writer. The transitioning signal is read
        # at the value it took AT that edge, since the order of one signal's
        # own records is the delta-cycle sequence and does carry meaning; that
        # is what keeps `changed(s),s=1` meaning "rising edge of s".
        #
        # Emission is per-record, so an event variable still counts each
        # trigger and an intra-tick 0->1->0 run still exposes each transition
        # (the 1.3.20 contract, and what `dump` shows). A clause requiring
        # SEVERAL signals to transition together is the exception: coincidence
        # is a property of the tick, not of any one record, so such a clause
        # reports the tick once.
        state = {}
        events = []
        total = 0
        truncated = False
        changed_set = set(changed_sids)
        multi_clauses = []      # clauses requiring several signals to coincide
        by_edge_sid = {}        # sid -> single-edge clauses that sid can fire
        for cl in clauses:
            edge_sids = [c['sid'] for c in cl if c['kind'] == 'changed']
            if len(edge_sids) > 1:
                multi_clauses.append(cl)
            else:
                by_edge_sid.setdefault(edge_sids[0], []).append(cl)

        stop = False
        for gt, group in _transition_groups(vcd, 0, t1, selected):
            if gt < t0:
                # Baseline: settled state strictly before t0. Event mode reports
                # changes within [t0, t1], so a change landing exactly at t0 is
                # in-window — this `< t0` deliberately differs from interval
                # mode's `<= t0` (level semantics) below; do not unify.
                for gsid, _gprev, gval, _gkind in group:
                    state[gsid] = gval
                continue

            # A change is an event-var trigger (every record counts) or a real
            # value transition; a first observation (prev is None) is not a
            # change, matching the pre-1.3.20 contract.
            tick_changed = set()
            edges = []
            for gsid, gprev, gval, gkind in group:
                if gkind == 'event' or (gprev is not None and gprev != gval):
                    tick_changed.add(gsid)
                    if gsid in changed_set:
                        edges.append((gsid, gval))
                state[gsid] = gval
            if not edges:
                continue

            fired = []      # (ov_sid, ov_val) per emitted row
            if any(_conditions_hold(state, cl, tick_changed) for cl in multi_clauses):
                # Coincidence is a tick property: report the tick once, with
                # every shown signal at its settled value.
                fired.append((None, None))
            else:
                for esid, edge_val in edges:
                    for cl in by_edge_sid.get(esid, ()):
                        if _conditions_hold(state, cl, tick_changed, esid, edge_val):
                            fired.append((esid, edge_val))
                            break
            for ov_sid, ov_val in fired:
                total += 1
                if limit != 0 and len(events) >= limit:
                    truncated = True
                    stop = True
                    break
                values, meta = _show_values(vcd, state, show_sids, verbose,
                                            ov_sid, ov_val)
                event = {'time_ticks': gt, 'time_h': fmt_time(gt, ts),
                         'values': values}
                if verbose:
                    event['meta'] = meta
                events.append(event)
            if stop:
                break

        if args.json:
            obj = {'mode': 'event', 'condition': cond_label,
                   'condition_resolved': cond_text,
                   'changed': [vcd.signals[sid]['path'] for sid in changed_sids],
                   'show': [vcd.signals[sid]['path'] for sid in show_sids],
                   'begin_ticks': t0, 'begin_h': fmt_time(t0, ts),
                   'end_ticks': t1, 'end_h': fmt_time(t1, ts),
                   'shown': len(events), 'truncated': truncated,
                   'events': events}
            obj.update(_trunc_hint(truncated, len(events), total, False, 'events'))
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
            print('No event in {}..{} where {}.'.format(
                fmt_time(t0, ts), fmt_time(t1, ts), cond_text))
        return

    # Interval/segment mode. A segment is an interval further split whenever
    # the displayed show-value tuple changes while the condition remains true.
    has_show = bool(show_sids)
    # Single-pass: build state up to t0, then process intervals t0+..t1
    state = {}
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

    active = False
    seg_start = None
    seg_values = None
    seg_meta = None
    init_checks_done = False

    # Interval mode is a STATE-per-timestamp query (unlike --changed's per-event
    # evaluation): _event_groups yields every value_change at one timestamp as a
    # group, which is applied together before the condition is evaluated once on
    # the resulting settled state. Reusing it removes the hand-rolled cur_t/group
    # regrouping and its duplicate 'final pending group' tail.
    for gt, ggroup in _event_groups(vcd, 0, t1, selected):
        if gt <= t0:
            for gsid, gval in ggroup:
                state[gsid] = gval
            continue

        if not init_checks_done:
            active = _any_clause_holds(state, clauses)
            seg_start = t0 if active else None
            if active and has_show:
                seg_values, seg_meta = _show_values(vcd, state, show_sids, verbose)
            init_checks_done = True

        # Apply this timestamp's group, then evaluate the condition on the
        # settled state.
        for gsid, gval in ggroup:
            state[gsid] = gval
        cond_ok = _any_clause_holds(state, clauses)
        if not has_show:
            if cond_ok and not active:
                active = True
                seg_start = gt
            elif not cond_ok and active:
                if append_result(emit_interval(seg_start, gt)):
                    break
                active = False
                seg_start = None
        else:
            if not cond_ok:
                if active:
                    row = emit_interval(seg_start, gt)
                    row['values'] = seg_values
                    if verbose:
                        row['meta'] = seg_meta
                    if append_result(row):
                        break
                    active = False
                    seg_start = None
                    seg_values = None
                    seg_meta = None
            else:
                new_values, new_meta = _show_values(vcd, state, show_sids, verbose)
                if not active:
                    active = True
                    seg_start = gt
                    seg_values = new_values
                    seg_meta = new_meta
                elif new_values != seg_values:
                    row = emit_interval(seg_start, gt)
                    row['values'] = seg_values
                    if verbose:
                        row['meta'] = seg_meta
                    if append_result(row):
                        break
                    seg_start = gt
                    seg_values = new_values
                    seg_meta = new_meta

    # If the selected signals produced no events in (t0, t1], the per-group init
    # check above never ran, so a condition that already holds across an
    # otherwise silent window would be missed (false "No interval"). Evaluate it
    # now from the baseline state; with no groups the final-interval emit below
    # reports the whole window.
    if not init_checks_done:
        active = _any_clause_holds(state, clauses)
        seg_start = t0 if active else None
        if active and has_show:
            seg_values, seg_meta = _show_values(vcd, state, show_sids, verbose)
        init_checks_done = True

    # Emit final interval if still active
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
               **_trunc_hint(truncated, len(results), total, False, key),
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
                    help='max rows/records to emit; default 500; 0 = unlimited; streaming commands stop after the first unshown result')
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
                   help='max rows/records to emit; default 500; 0 = unlimited; streaming commands stop after the first unshown result')
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
    sp.add_argument('--condition', metavar='COND', required=True, action='append',
                    help='comma-separated AND terms: SIG=VAL, SIG!=VAL, or changed(SIG); '
                         '!= does not match x/z/undef. Repeat the flag to OR the clauses '
                         '(there is no in-string OR). A changed(SIG) term switches to event '
                         'mode; then every clause must carry one')
    sp.add_argument('--show', metavar='PAT1,PAT2,...', type=_normalize_filter_patterns,
                    help='signals to display while the condition holds; output segments split when shown values change')
    sp.add_argument('--changed', metavar='PATTERN', default=None,
                    help=argparse.SUPPRESS)

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)
    if getattr(args, 'changed', None) is not None:
        # Removed in 1.5.0: the flag's event mode was a variant of --condition
        # wearing a flag's clothes, and being a flag it applied to the whole
        # query — an edge could not be scoped to one OR clause, and two signals
        # could not be required to transition together.
        sys.exit('Error: --changed was removed; write the edge as a condition term instead: '
                 '--condition "changed({})"'.format(args.changed))

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
    except _LimitParseError as e:
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
    # Verbatim VCD text and ensure_ascii=False JSON can carry non-ASCII
    # characters (signal paths, $version/$date strings). Force UTF-8 so a
    # legacy Windows codepage cannot turn a valid dump into a
    # UnicodeEncodeError. No-op where reconfigure() is unavailable.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError, OSError):
            pass
    try:
        main()
    except KeyboardInterrupt:
        # Conventional 128 + SIGINT(2): a clean exit, no traceback.
        sys.exit(130)
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        sys.exit(0)