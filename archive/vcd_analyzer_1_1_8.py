#!/usr/bin/env python3
"""VCD waveform analyzer for Agent-based RTL debug.

Usage: vcd_analyzer [--json] <command> <file> [options]

Commands:
  info       <file>                               File overview (timescale, signal count, time span, scopes)
  list       <file> [--filter K1,K2]               List signals with path and bit width
  dump       <file> [--begin T] [--end T] [--filter K1,K2]   Print signal value changes in time order
  summary    <file> [--begin T] [--end T] [--filter K1,K2]   Per-signal stats: change count, unique values, static detection
  edges      <file> [--begin T] [--end T] [--filter K1,K2]   1-bit edge detection with frequency estimation
  snapshot   <file> --at T [--filter K1,K2]        Known signal values at a given time point
  compare    <file> --at T1,T2 [--filter K1,K2]    Diff signal values between two time points
  search     <file> --value V [--signal K] [--begin T] [--end T] [--filter K1,K2]   Find intervals where signal state equals a value

Global option:
  --json    Output structured JSON instead of text (for programmatic parsing)

Argument formats:
  <file>          VCD file path
  --filter K1,K2  Comma-separated keywords, substring-matched against signal paths (case-insensitive)
                  e.g. --filter clk,rst   --filter tdata,tvalid   --filter u_dll_ctrl
  --begin T       Start time with optional unit suffix: 0, 100ns, 17.5us, 1ms, 500ps, 200fs
  --end T         End time, same format as --begin. Omit for no upper bound
  --at T          Time point for snapshot. For compare: two points comma-separated: --at 17.5us,17.7us
  --value V       Target value for search: decimal (42), hex (0x2a),
                  or binary with explicit prefix (0b101010 or b101010).
                  Leading-zero forms like "0010" parse as decimal 10;
                  use "0b0010" to mean binary 2.
  --signal K      Additional keyword filter for search, targets signal name specifically

Examples:
  vcd_analyzer info sim.vcd
  vcd_analyzer list sim.vcd --filter tdata,tvalid,tready
  vcd_analyzer dump sim.vcd --begin 17.5us --end 17.6us --filter clk,rst,state
  vcd_analyzer summary sim.vcd --filter dll_st,locked
  vcd_analyzer edges sim.vcd --filter clk_500M
  vcd_analyzer snapshot sim.vcd --at 17.55us --filter init_done,state
  vcd_analyzer compare sim.vcd --at 17.535us,17.56us --filter init_done,link_active,state
  vcd_analyzer search sim.vcd --signal state --value 5
  vcd_analyzer search sim.vcd --value 0xff --begin 100ns --end 500ns
  vcd_analyzer --json summary sim.vcd --filter tvalid,tready
"""

__version__ = '1.1.8'

import sys
import os
import re
import json
import argparse
from collections import defaultdict

# -- Time utilities ----------------------------------------------------------

_UNITS = {'fs': 1e-15, 'ps': 1e-12, 'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}

# IEEE 1364-2005 18.2.2 real value_change is 'r' + real_number where
# real_number follows C99 printf("%g") shape: optional sign, integer and/or
# fractional digits, optional exponent. Used to reject garbage tokens like
# 'reset' that start with 'r' but aren't a numeric value_change.
_REAL_RE = re.compile(r'^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$')

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
    """Extract base time unit in seconds from $timescale line."""
    m = re.search(r'(\d+)\s*(fs|ps|ns|us|ms|s)', text)
    return int(m.group(1)) * _UNITS[m.group(2)] if m else 1e-12


class _TimeParseError(ValueError):
    """Raised by parse_time on invalid input; caught in main() for friendly CLI errors."""


def parse_time(s, ts_sec):
    """Parse time string with optional unit suffix to internal VCD timestamp.

    VCD timestamps per IEEE 1364-2005 18.2.3.8 are non-negative integers.
    - With unit: any positive value, scaled to ticks (e.g. '17.5us')
    - Without unit: must be a non-negative integer tick count

    Bare '10.5' (no unit) is rejected to avoid silent int() truncation;
    use '10.5ns' to specify a fractional time.
    """
    if s is None:
        return None
    m = re.match(r'^([0-9]*\.?[0-9]+)\s*(fs|ps|ns|us|ms|s)?$', s.strip())
    if not m:
        # Fall back to bare integer ('100', '-5'); reject anything else.
        try:
            v = int(s)
        except (ValueError, TypeError):
            raise _TimeParseError(
                'invalid time value {!r}; expected integer ticks or value '
                'with fs/ps/ns/us/ms/s suffix'.format(s))
        if v < 0:
            raise _TimeParseError(
                'time must be non-negative; got {!r}'.format(s))
        return v
    val_str, unit = m.group(1), m.group(2)
    if unit is None:
        if '.' in val_str:
            raise _TimeParseError(
                'bare numeric time must be integer ticks; got {!r}. '
                'Use a unit suffix for fractional times, e.g. {}ns'.format(s, val_str))
        return int(val_str)
    return int(round(float(val_str) * _UNITS[unit] / ts_sec))


def fmt_time(ts, ts_sec):
    """Format internal timestamp to human-readable string.

    Picks the smallest unit u where |scaled| < 1000, preferring natural
    boundaries. E.g. with timescale 1ns, #5 prints as '5ns' not '5000ps';
    #17534700 prints as '17.5347us'.
    """
    if ts == 0:
        return '0s'
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
    """Try converting to int, None on x/z."""
    if 'x' in value or 'z' in value:
        return None
    try:
        return int(value, 2) if len(value) > 1 else int(value)
    except ValueError:
        return None


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
        # If $enddefinitions $end is followed by data tokens on the same
        # line(s) buffered by readline, those tokens replay first in data.
        self._initial_tokens = []
        self._bit_map = {}          # sym -> (sig_id, bit_index)
        self._bit_state = {}        # sig_id -> [bit_val] * width
        self._parse_header()

    def _parse_header(self):
        """Token-based header parse. Sections may span multiple lines;
        $end is the only terminator (IEEE 1364-2005 18.2.1)."""
        scope = []
        raw_vars = []  # (sym, name, width, bit_idx_str, scope_path, vtype)
        current_kw = None
        body = []
        done = False

        with open(self.path, 'r', errors='replace') as f:
            while not done:
                line = f.readline()
                if not line:
                    break
                for tok in line.split():
                    if done:
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
                            scope.append(body[1])
                        elif current_kw == '$upscope':
                            if scope:
                                scope.pop()
                        elif current_kw == '$var' and len(body) >= 4:
                            vtype = body[0]
                            try:
                                w = int(body[1])
                            except ValueError:
                                m = re.match(r'\[(\d+):(\d+)\]', body[1])
                                if m:
                                    w = abs(int(m.group(1)) - int(m.group(2))) + 1
                                else:
                                    current_kw = None
                                    continue
                            sym, name = body[2], body[3]
                            # Per IEEE 1364 free-format, the bracket reference
                            # range can be split into several tokens, e.g.
                            # 'data [7 : 0]' → ['data', '[7', ':', '0]'].
                            # Collect tokens from body[4] until one ends with
                            # ']' and join (split() already dropped whitespace).
                            bit_str = None
                            if len(body) > 4 and body[4].startswith('['):
                                parts = []
                                for t in body[4:]:
                                    parts.append(t)
                                    if ']' in t:
                                        break
                                if parts and ']' in parts[-1]:
                                    bit_str = ''.join(parts)
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
                            raw_vars.append((sym, name, w, bit_str, '.'.join(scope), vtype))
                        elif current_kw == '$enddefinitions':
                            done = True
                        # $comment, $date, $version: drop body
                        current_kw = None
                    else:
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
        standalone = []
        bit_select_singletons = []       # (sym, name, idx, sc, vtype)

        for sym, name, w, bit_str, sc, vtype in raw_vars:
            if w == 1 and bit_str is not None:
                m = re.match(r'\[(\d+)\]', bit_str)
                if m:
                    idx = int(m.group(1))
                    bit_groups[(sc, name)][idx] = sym
                    bit_types[(sc, name)] = vtype
                    bit_select_singletons.append((sym, name, idx, sc, vtype))
                    continue
            standalone.append((sym, name, w, sc, vtype))

        # Partition bit_groups: contiguous-from-0 with ≥2 bits → reassemble;
        # everything else → individual bit-select references. A single
        # '[0]' declaration alone is NOT a bus — it's a partial dump that
        # happens to use bit 0; synthesizing it as 'data[0:0]' would lie
        # about the file structure.
        non_contiguous = set()
        for key, bits in bit_groups.items():
            indices = set(bits.keys())
            if len(indices) < 2 or indices != set(range(max(indices) + 1)):
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
            else:
                self.signals[sym] = {
                    'path': path, 'width': w, 'type': vtype, 'aliases': [path]
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
                'aliases': [path],
                'synthesized': True,    # bit-exploded reassembled bus
                'raw_bits': len(bits),  # number of $var declarations consumed
            }
            self._bit_state[sig_id] = ['x'] * width
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
        """Return set of sig_ids matching any keyword, or None for all.

        Matches against any aliased path of a signal.
        """
        if not keywords:
            return None
        kws = [k.lower() for k in keywords]
        out = set()
        for sid, info in self.signals.items():
            for path in info['aliases']:
                pl = path.lower()
                if any(k in pl for k in kws):
                    out.add(sid)
                    break
        return out

    def _data_tokens(self):
        """Generator yielding all tokens from the data section."""
        for t in self._initial_tokens:
            yield t
        with open(self.path, 'r', errors='replace') as f:
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
                new_t = int(tok[1:])
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
                if not _REAL_RE.match(body):
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
                val = _PORT_STATE.get(state, 'x')
            else:
                continue  # unparseable token

            # Catch-up before t0: update bit_state only, don't emit
            if cur_t < t0:
                if sym in self._bit_map:
                    for gid, idx in self._bit_map[sym]:
                        self._bit_state[gid][idx] = val
                continue

            # Bit-exploded signal: aggregate into virtual bus value(s).
            # If the same identifier_code drives multiple synthesized buses
            # (via aliased parent declarations), each gets its own event.
            if sym in self._bit_map:
                for gid, idx in self._bit_map[sym]:
                    self._bit_state[gid][idx] = val
                    if sids is not None and gid not in sids:
                        continue
                    pending[gid] = ''.join(reversed(self._bit_state[gid]))
                continue

            # Standalone signal
            if sym not in self.signals:
                continue
            if sids is not None and sym not in sids:
                continue
            pending[sym] = val

        # Final flush
        if cur_t >= t0:
            for sid, val in _flush():
                yield cur_t, sid, val

    def scan_time_range(self):
        """Min/max timestamps in the file. If any value_change occurs before
        the first #T (an initial $dumpvars block), t_min is 0. Time is
        observed-max (never less than the largest seen): malformed VCDs
        with timestamps going backwards don't produce negative duration.
        $comment / $vcdclose / unknown $keyword bodies are skipped only
        when at a top-level position. Value-change body validation matches
        iter_events so info/dump don't disagree on the same file."""
        t_min = t_max = None
        saw_initial_data = False
        raw = self._data_tokens()
        pushback = []
        def _next():
            return pushback.pop() if pushback else next(raw, None)
        def _is_struct(t):
            if t is None: return True
            if t.startswith('#') and len(t) > 1 and t[1].isdigit():
                # Declared identifier_code with #-form is not a timestamp
                return t not in self.signals and t not in self._bit_map
            return False

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
                try:
                    t = int(tok[1:])
                except ValueError:
                    continue
                if t_min is None:
                    t_min = 0 if saw_initial_data else t
                t_max = t if t_max is None else max(t_max, t)
                continue
            # Value-change branches with body validation
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
                if not _REAL_RE.match(tok[1:]):
                    continue
                sym = _next()
                if _is_struct(sym):
                    if sym is not None:
                        pushback.append(sym)
                    continue
                if t_min is None:
                    saw_initial_data = True
            elif first == 'p':
                # Validate strength tokens before consuming further
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
        if t_min is None and saw_initial_data:
            t_min = t_max = 0
        return t_min, t_max


# -- Subcommands -------------------------------------------------------------

def cmd_info(vcd, args):
    t_min, t_max = vcd.scan_time_range()
    ts = vcd.ts_sec
    # Counts come from the raw $var declarations (transparent to spec)
    # rather than post-reassembly aliases. A 512-bit bit-exploded bus
    # contributes 512 wire declarations to var_types, not 1, so agents
    # can see actual file size. signal_count remains the post-reassembly
    # count (what the downstream commands operate on).
    synth = [s for s in vcd.signals.values() if s.get('synthesized')]
    r = {
        'file': vcd.path,
        'size_bytes': os.path.getsize(vcd.path),
        'timescale': vcd.ts_str.replace('$timescale', '').replace('$end', '').strip(),
        'signal_count': len(vcd.signals),       # post-reassembly
        'reference_count': vcd.raw_var_count,   # raw $var declarations
        'synthesized_buses': len(synth),        # reassembled bit-bus groups
        'var_types': dict(sorted(vcd.raw_type_counts.items(), key=lambda x: -x[1])),
        'time_min': fmt_time(t_min, ts) if t_min is not None else None,
        'time_max': fmt_time(t_max, ts) if t_max is not None else None,
        'duration': fmt_time(t_max - t_min, ts) if t_min is not None and t_max is not None else None,
        'scopes': sorted(set(
            '.'.join(v['path'].split('.')[:-1]) for v in vcd.signals.values() if '.' in v['path']
        )),
    }
    if args.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print('File      : {}'.format(r['file']))
        print('Size      : {:,} bytes'.format(r['size_bytes']))
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


def cmd_list(vcd, args):
    sids = vcd.match(args.filter)
    entries = []
    for sid, info in vcd.signals.items():
        if sids is not None and sid not in sids:
            continue
        # Each aliased path appears as a separate row. Per IEEE 1364-2005
        # 18.2.3.7, multiple paths can share one identifier_code.
        vtype = info.get('type', 'wire')
        for path in info['aliases']:
            entries.append({'path': path, 'width': info['width'], 'type': vtype})
    entries.sort(key=lambda e: e['path'])
    if args.json:
        print(json.dumps(entries, indent=2, ensure_ascii=False))
    else:
        for e in entries:
            print('  {:<60} {:>5}  {}'.format(e['path'], e['width'], e['type']))
        print('\nTotal: {}'.format(len(entries)))


def cmd_dump(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    sids = vcd.match(args.filter)
    if args.json:
        # Flat event list; one record per value change. Easier to filter/map
        # in downstream tools (jq, agent code) than nested-by-timestamp form.
        events = []
        for t, sid, val in vcd.iter_events(t0, t1, sids):
            info = vcd.signals[sid]
            events.append({
                'time': t,
                'time_h': fmt_time(t, ts),
                'path': info['path'],
                'value': fmt_val(val, info),
            })
        print(json.dumps(events, indent=2, ensure_ascii=False))
        return
    cur_t, count = None, 0
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        if t != cur_t:
            cur_t = t
            print('\n[T={}] ({})'.format(t, fmt_time(t, ts)))
        print('  {:<55} = {}'.format(vcd.signals[sid]['path'], fmt_val(val, vcd.signals[sid])))
        count += 1
    if count == 0:
        print('(no changes in range)')
    else:
        print('\n{} changes'.format(count))


def cmd_summary(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    if t1 is not None and t1 < t0:
        raise _TimeParseError('end time must be >= begin time')
    sids = _selected_sids(vcd, vcd.match(args.filter))

    initial = _build_snapshot(vcd, t0, sids)
    stats = {}
    for sid, val in initial.items():
        stats[sid] = {
            'changes': 0, 'first_at': None, 'last_at': t0,
            'initial': val, 'last': val, 'unique': {val}
        }

    for t, sid, val in vcd.iter_events(t0, t1, sids):
        if sid not in stats:
            stats[sid] = {
                'changes': 0, 'first_at': None, 'last_at': t,
                'initial': None, 'last': None, 'unique': set()
            }
        s = stats[sid]
        s['changes'] += 1
        if s['first_at'] is None:
            s['first_at'] = t
        s['last_at'] = t
        s['last'] = val
        s['unique'].add(val)

    rows = []
    for sid in sorted(stats, key=lambda s: vcd.signals[s]['path']):
        info, s = vcd.signals[sid], stats[sid]
        cat = 'static' if s['changes'] == 0 and s['initial'] is not None else 'active'
        rows.append({
            'path': info['path'], 'width': info['width'], 'category': cat,
            'changes': s['changes'], 'unique': len(s['unique']),
            'initial_val': fmt_val(s['initial'], info) if s['initial'] is not None else '(undef)',
            'last_val': fmt_val(s['last'], info) if s['last'] is not None else '(undef)',
            'first_change_at': fmt_time(s['first_at'], ts) if s['first_at'] is not None else None,
            'last_change_at': fmt_time(s['last_at'], ts) if s['changes'] else None,
        })

    active = [r for r in rows if r['category'] == 'active']
    static = [r for r in rows if r['category'] == 'static']
    limit = max(0, getattr(args, 'limit', 50))

    if args.json:
        clipped = rows if limit == 0 else rows[:limit]
        print(json.dumps({
            'begin': fmt_time(t0, ts),
            'end': fmt_time(t1, ts) if t1 is not None else None,
            'total': len(rows), 'active': len(active), 'static': len(static),
            'truncated': limit != 0 and len(rows) > limit,
            'rows': clipped,
        }, indent=2, ensure_ascii=False))
    else:
        print('Summary: {} known signals ({} active, {} static)'.format(
            len(rows), len(active), len(static)))
        if active:
            print('\nActive ({}):{}'.format(
                len(active), ' [showing first {}]'.format(limit) if limit and len(active) > limit else ''))
            for r in (active if limit == 0 else active[:limit]):
                print('  {:<45} w={:<4} chg={:<6} uniq={:<4} init={} last={}'.format(
                    r['path'], r['width'], r['changes'], r['unique'],
                    r['initial_val'], r['last_val']))
        if static:
            s_limit = limit if limit else len(static)
            print('\nStatic known ({}):{}'.format(
                len(static), ' [showing first {}]'.format(s_limit) if len(static) > s_limit else ''))
            for r in static[:s_limit]:
                print('  {:<55} = {}'.format(r['path'], r['last_val']))
        if not rows:
            print('(no known values in the selected time range)')

def cmd_edges(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    sids = vcd.match(args.filter)
    prev = {}
    # Pre-window state replay: standalone 1-bit signals need their last
    # value before t0 known, otherwise the first transition inside the
    # window can't be classified as rise vs fall (the first event has no
    # 'prev' to compare against). iter_events already maintains bit_state
    # for bit-exploded signals during catch-up; we do the same for
    # standalones here. Only runs when t0 > 0; cost is one extra header-to-t0
    # scan, amortized across edge counting.
    if t0 > 0:
        for t, sid, val in vcd.iter_events(0, t0 - 1, sids):
            if vcd.signals[sid]['width'] == 1:
                prev[sid] = val
    edges = defaultdict(list)  # sid -> [(time, 'rise'|'fall')]
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        if vcd.signals[sid]['width'] != 1:
            continue
        if sid in prev:
            if prev[sid] == '0' and val == '1':
                edges[sid].append((t, 'rise'))
            elif prev[sid] == '1' and val == '0':
                edges[sid].append((t, 'fall'))
        prev[sid] = val

    results = []
    for sid in sorted(edges, key=lambda s: vcd.signals[s]['path']):
        el = edges[sid]
        rise_t = [t for t, e in el if e == 'rise']
        period, freq = None, None
        if len(rise_t) >= 2:
            intervals = [rise_t[i+1] - rise_t[i] for i in range(min(len(rise_t)-1, 50))]
            avg = sum(intervals) / len(intervals)
            # Pass float directly; fmt_time handles non-integer ticks. Avoids
            # period/freq inconsistency on jittery clocks (e.g. avg=2.5ns
            # would otherwise display T=2ns alongside f=400MHz).
            period = fmt_time(avg, ts)
            ps = avg * ts
            if ps > 0:
                hz = 1.0 / ps
                freq = '{:.2f} GHz'.format(hz/1e9) if hz >= 1e9 else \
                       '{:.2f} MHz'.format(hz/1e6) if hz >= 1e6 else \
                       '{:.2f} KHz'.format(hz/1e3) if hz >= 1e3 else \
                       '{:.2f} Hz'.format(hz)
        r = {'path': vcd.signals[sid]['path'],
             'rise': sum(1 for _, e in el if e == 'rise'),
             'fall': sum(1 for _, e in el if e == 'fall')}
        if period:
            r['period'] = period
            r['freq'] = freq
        results.append(r)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for r in results:
            line = '  {:<50} rise={} fall={}'.format(r['path'], r['rise'], r['fall'])
            if 'period' in r:
                line += '  T={} f={}'.format(r['period'], r['freq'])
            print(line)



def _selected_sids(vcd, sids):
    """Return an explicit set of selected signal ids."""
    return set(vcd.signals.keys()) if sids is None else set(sids)


def _build_snapshot(vcd, t_at, sids=None):
    """Replay from start to t_at, return known {sig_id: value} only."""
    state = {}
    for t, sid, val in vcd.iter_events(0, t_at, sids):
        state[sid] = val
    return state


def _parse_target_value(text):
    """Parse search target once. Raw string is kept for x/z matches;
    integer form is used for width-independent numeric matches."""
    raw = text.lower().strip()
    intval = None
    try:
        if raw.startswith(('0x', '0X')):
            intval = int(raw, 16)
        elif raw.startswith('0b'):
            intval = int(raw[2:], 2)
        elif raw.startswith('b'):
            intval = int(raw[1:], 2)
        else:
            intval = int(raw)
    except ValueError:
        pass
    return raw, intval


def _value_matches(value, target_raw, target_int):
    if value == target_raw:
        return True
    if target_int is None:
        return False
    iv = val_to_int(value)
    return iv is not None and iv == target_int


def _signal_value_intervals(vcd, t0, t1, sids):
    """Yield stable known-value intervals per selected signal.

    Each item is (sid, start_t, end_t, value). Unknown time before a signal's
    first observed value is omitted rather than guessed as x/undef.
    """
    state = _build_snapshot(vcd, t0, sids)
    start = {sid: t0 for sid in state}
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        if t <= t0:
            continue
        if sid in state:
            yield sid, start[sid], t, state[sid]
        state[sid] = val
        start[sid] = t
    end_t = t1
    if end_t is None:
        _mn, mx = vcd.scan_time_range()
        end_t = mx if mx is not None else t0
    for sid, val in state.items():
        yield sid, start[sid], end_t, val

def cmd_snapshot(vcd, args):
    ts = vcd.ts_sec
    t_at = parse_time(args.at, ts)
    sids = vcd.match(args.filter)
    state = _build_snapshot(vcd, t_at, sids)
    rows = []
    for sid in sorted(state, key=lambda s: vcd.signals[s]['path']):
        info = vcd.signals[sid]
        rows.append({'path': info['path'], 'value': fmt_val(state[sid], info)})
    if args.json:
        print(json.dumps({'at': fmt_time(t_at, ts), 'signals': rows}, indent=2, ensure_ascii=False))
    else:
        print('Known snapshot @ {}'.format(fmt_time(t_at, ts)))
        for r in rows:
            print('  {:<55} = {}'.format(r['path'], r['value']))
        print('\n{} known signals'.format(len(rows)))
        if not rows:
            print('(no known values at this time point)')

def cmd_compare(vcd, args):
    ts = vcd.ts_sec
    parts = args.at.split(',')
    if len(parts) != 2:
        sys.exit('Error: --at needs two times separated by comma, e.g. --at 17.5us,17.7us')
    ta, tb = parse_time(parts[0].strip(), ts), parse_time(parts[1].strip(), ts)
    sids = vcd.match(args.filter)
    # Build both snapshots independently from t=0 — avoids the
    # directionality bug where --at T2,T1 (with T1<T2 already replayed)
    # would silently report no diffs. Each snapshot is the true state at
    # its query time regardless of ordering.
    sa = _build_snapshot(vcd, ta, sids)
    sb = _build_snapshot(vcd, tb, sids)

    diffs = []
    for sid in sorted(set(sa) | set(sb), key=lambda s: vcd.signals[s]['path']):
        va, vb = sa.get(sid), sb.get(sid)
        if va != vb:
            info = vcd.signals[sid]
            diffs.append({
                'path': info['path'],
                'at_t1': fmt_val(va, info) if va else '(undef)',
                'at_t2': fmt_val(vb, info) if vb else '(undef)',
            })
    if args.json:
        print(json.dumps({'t1': fmt_time(ta, ts), 't2': fmt_time(tb, ts),
                          'diffs': diffs}, indent=2, ensure_ascii=False))
    else:
        print('Compare: {} vs {}'.format(fmt_time(ta, ts), fmt_time(tb, ts)))
        print('{} changed, {} unchanged'.format(len(diffs), len(set(sa) | set(sb)) - len(diffs)))
        for d in diffs:
            print('  {:<48} {} -> {}'.format(d['path'], d['at_t1'], d['at_t2']))


def cmd_search(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    if args.end:
        t1 = parse_time(args.end, ts)
    else:
        _mn, mx = vcd.scan_time_range()
        t1 = mx if mx is not None else t0
    if t1 < t0:
        raise _TimeParseError('end time must be >= begin time')

    flt = [args.signal] if args.signal else args.filter
    sids0 = vcd.match(flt)
    sids = _selected_sids(vcd, sids0)
    if not sids:
        msg = 'No signals match the given filter'
        if args.json:
            print(json.dumps({'begin': fmt_time(t0, ts), 'end': fmt_time(t1, ts),
                              'total': 0, 'matches': [], 'message': msg},
                             indent=2, ensure_ascii=False))
        else:
            print(msg)
        return

    target_raw, target_int = _parse_target_value(args.value)
    matches = []
    known_sids = set()
    for sid, a, b, val in _signal_value_intervals(vcd, t0, t1, sids):
        known_sids.add(sid)
        if _value_matches(val, target_raw, target_int):
            info = vcd.signals[sid]
            matches.append({
                'start': fmt_time(a, ts), 'end': fmt_time(b, ts),
                'path': info['path'], 'value': fmt_val(val, info),
            })

    limit = max(0, getattr(args, 'limit', 200))
    shown = matches if limit == 0 else matches[:limit]
    if args.json:
        print(json.dumps({
            'begin': fmt_time(t0, ts), 'end': fmt_time(t1, ts),
            'searched_signals': len(sids), 'defined_signals': len(known_sids),
            'target': args.value, 'total': len(matches),
            'truncated': limit != 0 and len(matches) > limit,
            'matches': shown,
        }, indent=2, ensure_ascii=False))
        return

    if matches:
        print('Found {} interval(s) where value == "{}":'.format(len(matches), args.value))
        for m in shown:
            print('  {:<14} .. {:<14} {:<50} = {}'.format(
                m['start'], m['end'], m['path'], m['value']))
        if limit and len(matches) > limit:
            print('  ... {} total'.format(len(matches)))
    else:
        if not known_sids:
            print('No defined values in {}..{} for selected signals'.format(
                fmt_time(t0, ts), fmt_time(t1, ts)))
        else:
            print('No interval in {}..{} where selected signals equal "{}"'.format(
                fmt_time(t0, ts), fmt_time(t1, ts), args.value))


# -- CLI entry ---------------------------------------------------------------

def _add_time_args(sp):
    sp.add_argument('--begin', metavar='TIME',
                    help='start time, e.g. 0, 100ns, 17.5us (omit = from start)')
    sp.add_argument('--end', metavar='TIME',
                    help='end time, same format (omit = no upper bound)')

def _add_filter(sp):
    sp.add_argument('--filter', metavar='K1,K2,...',
                    type=lambda s: [k.strip() for k in s.split(',') if k.strip()],
                    help='comma-separated keywords, substring-matched against signal paths')

def main():
    p = argparse.ArgumentParser(
        prog='vcd_analyzer',
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--json', action='store_true',
                   help='output structured JSON instead of human-readable text')
    p.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    sub = p.add_subparsers(dest='cmd', metavar='<command>')

    sp = sub.add_parser('info', help='file overview: timescale, signal count, time span, scopes')
    sp.add_argument('file', metavar='<file>', help='VCD file path')

    sp = sub.add_parser('list', help='list signals with path and bit width')
    sp.add_argument('file', metavar='<file>'); _add_filter(sp)

    sp = sub.add_parser('dump', help='print signal value changes in time order')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp)

    sp = sub.add_parser('summary', help='per-signal stats over a time window, including carried static known values')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp)
    sp.add_argument('--limit', type=int, default=50, help='max rows to print/return; 0 = unlimited')

    sp = sub.add_parser('edges', help='1-bit edge detection with frequency estimation')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp)

    sp = sub.add_parser('snapshot', help='known signal values at a given time point')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='TIME', required=True, help='time point, e.g. 17.55us')
    _add_filter(sp)

    sp = sub.add_parser('compare', help='diff signal values between two time points')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='T1,T2', required=True, help='two time points comma-separated, e.g. 17.5us,17.7us')
    _add_filter(sp)

    sp = sub.add_parser('search', help='find stable intervals where signal state equals a value')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp)
    sp.add_argument('--signal', metavar='KEYWORD', help='keyword to narrow which signals to search')
    sp.add_argument('--value', metavar='VAL', required=True,
                    help='target value: decimal (42), hex (0x2a), or binary (101010)')
    sp.add_argument('--limit', type=int, default=200, help='max intervals to print/return; 0 = unlimited')

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)

    # Friendly errors for common CLI mistakes (no Python traceback to user).
    # Time-arg parsing happens lazily inside each cmd via parse_time(); we
    # surface those as concise errors here.
    try:
        vcd = VCDParser(args.file)
        cmds = {'info': cmd_info, 'list': cmd_list, 'dump': cmd_dump, 'summary': cmd_summary,
                'edges': cmd_edges, 'snapshot': cmd_snapshot,
                'compare': cmd_compare, 'search': cmd_search}
        cmds[args.cmd](vcd, args)
    except FileNotFoundError as e:
        sys.exit('Error: cannot open VCD file: {}'.format(e.filename or args.file))
    except IsADirectoryError as e:
        sys.exit('Error: not a file: {}'.format(e.filename or args.file))
    except PermissionError as e:
        sys.exit('Error: permission denied: {}'.format(e.filename or args.file))
    except _TimeParseError as e:
        sys.exit('Error: ' + str(e))


if __name__ == '__main__':
    # Make `vcd_analyzer ... | head` and similar CLI pipelines work cleanly
    # without spewing BrokenPipeError tracebacks. On POSIX, restoring SIGPIPE
    # to SIG_DFL causes Python to die silently as a real Unix tool would.
    # On Windows there's no SIGPIPE; fall back to catching the exception.
    import signal as _sig
    if hasattr(_sig, 'SIGPIPE'):
        _sig.signal(_sig.SIGPIPE, _sig.SIG_DFL)
    try:
        main()
    except BrokenPipeError:
        # Reroute stdout to devnull so the interpreter's final flush at exit
        # doesn't raise a second BrokenPipeError on the already-broken pipe.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        sys.exit(0)
