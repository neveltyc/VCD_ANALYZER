#!/usr/bin/env python3
"""VCD waveform analyzer for Agent-based RTL debug.

Usage: vcd_analyzer [--json] <command> <file> [options]

Commands:
  info       <file>                               File overview (timescale, signal count, time span, scopes)
  list       <file> [--filter K1,K2]               List signals with path and bit width
  dump       <file> [--begin T] [--end T] [--filter K1,K2]   Print signal value changes in time order
  summary    <file> [--begin T] [--end T] [--filter K1,K2]   Per-signal stats: change count, unique values, static detection
  edges      <file> [--begin T] [--end T] [--filter K1,K2]   1-bit edge detection with frequency estimation
  handshake  <file> [--begin T] [--end T] [--filter K1,K2]   AXI-Stream valid&ready transfer analysis
  snapshot   <file> --at T [--filter K1,K2]        All signal values at a given time point
  compare    <file> --at T1,T2 [--filter K1,K2]    Diff signal values between two time points
  search     <file> --value V [--signal K] [--begin T] [--end T] [--filter K1,K2]   Find when signal equals a value

Global option:
  --json    Output structured JSON instead of text (for programmatic parsing)

Argument formats:
  <file>          VCD file path
  --filter K1,K2  Comma-separated keywords, substring-matched against signal paths (case-insensitive)
                  e.g. --filter clk,rst   --filter tdata,tvalid   --filter u_dll_ctrl
  --begin T       Start time with optional unit suffix: 0, 100ns, 17.5us, 1ms, 500ps, 200fs
  --end T         End time, same format as --begin. Omit for no upper bound
  --at T          Time point for snapshot. For compare: two points comma-separated: --at 17.5us,17.7us
  --value V       Target value for search: decimal (42), hex (0x2a), or binary (101010)
  --signal K      Additional keyword filter for search, targets signal name specifically

Examples:
  vcd_analyzer info sim.vcd
  vcd_analyzer list sim.vcd --filter tdata,tvalid,tready
  vcd_analyzer dump sim.vcd --begin 17.5us --end 17.6us --filter clk,rst,state
  vcd_analyzer summary sim.vcd --filter dll_st,locked
  vcd_analyzer edges sim.vcd --filter clk_500M
  vcd_analyzer handshake sim.vcd --filter us_s --begin 17.5us
  vcd_analyzer snapshot sim.vcd --at 17.55us --filter init_done,state
  vcd_analyzer compare sim.vcd --at 17.535us,17.56us --filter init_done,link_active,state
  vcd_analyzer search sim.vcd --signal state --value 5
  vcd_analyzer search sim.vcd --value 0xff --begin 100ns --end 500ns
  vcd_analyzer --json summary sim.vcd --filter tvalid,tready
"""

__version__ = '1.0.0'

import sys
import os
import re
import json
import argparse
from collections import defaultdict

# -- Time utilities ----------------------------------------------------------

_UNITS = {'fs': 1e-15, 'ps': 1e-12, 'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}

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


def parse_time(s, ts_sec):
    """Parse time string with optional unit suffix to internal VCD timestamp."""
    if s is None:
        return None
    m = re.match(r'^([0-9]*\.?[0-9]+)\s*(fs|ps|ns|us|ms|s)?$', s.strip())
    if not m:
        return int(s)
    val, unit = float(m.group(1)), m.group(2)
    return int(val) if unit is None else int(round(val * _UNITS[unit] / ts_sec))


def fmt_time(ts, ts_sec):
    """Format internal timestamp to human-readable string."""
    sec = ts * ts_sec
    for u in ('fs', 'ps', 'ns', 'us', 'ms', 's'):
        scaled = sec / _UNITS[u]
        if 0.1 <= abs(scaled) < 10000 or u == 's':
            return '{:g}{}'.format(scaled, u)
    return '{:g}s'.format(sec)


# -- Value formatting --------------------------------------------------------

def fmt_val(value, info):
    """Format signal value per IEEE 1364-2005 18.2.2.

    info: dict with 'width' (required) and 'type' (optional, default 'wire').

    Width==1 covers both 1-bit scalars (0/1/x/z) and real numbers (rendered
    as decimal string by the simulator using %.16g). Multi-bit values are
    left-extended per Table 18-1: MSB X/Z extends with X/Z, else 0.
    Events (var_type 'event' per 18.2.3.7) display as 'triggered' since the
    dumped value is just a marker (18.2.2).
    """
    width = info['width']
    vtype = info.get('type', 'wire')
    if vtype == 'event':
        return 'triggered'
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

class VCDParser:
    """Streaming VCD parser. Auto-reassembles QuestaSim bit-exploded signals."""

    def __init__(self, path):
        self.path = path
        self.ts_str = ''
        self.ts_sec = 1e-12        # timescale in seconds
        self.signals = {}           # sig_id -> {path, width}
        self._data_offset = 0
        # Bit reassembly: sym -> (sig_id, bit_index)
        self._bit_map = {}
        # sig_id -> [None]*width for bit-exploded signals
        self._bit_state = {}
        self._parse_header()

    def _parse_header(self):
        scope = []
        raw_vars = []  # (symbol, name, width, bit_idx_str, scope_path)
        with open(self.path, 'r', errors='replace') as f:
            while True:
                line = f.readline()
                if not line:
                    break
                s = line.strip()
                if s.startswith('$timescale'):
                    buf = s
                    while '$end' not in buf:
                        buf += ' ' + f.readline().strip()
                    self.ts_str = buf
                    self.ts_sec = _parse_timescale(buf)
                elif s.startswith('$scope'):
                    p = s.split()
                    if len(p) >= 3:
                        scope.append(p[2])
                elif s.startswith('$upscope'):
                    if scope:
                        scope.pop()
                elif s.startswith('$var'):
                    p = s.split()
                    if len(p) >= 5:
                        vtype = p[1]
                        # Width is normally an integer, but extended VCD ports
                        # can use [msb:lsb] form per IEEE 1364-2005 18.4.2.
                        try:
                            w = int(p[2])
                        except ValueError:
                            m = re.match(r'\[(\d+):(\d+)\]', p[2])
                            if not m:
                                continue
                            w = abs(int(m.group(1)) - int(m.group(2))) + 1
                        sym, name = p[3], p[4]
                        bit_str = p[5] if len(p) >= 7 and p[5].startswith('[') else None
                        raw_vars.append((sym, name, w, bit_str, '.'.join(scope), vtype))
                elif s.startswith('$enddefinitions'):
                    while '$end' not in s:
                        s = f.readline().strip()
                    self._data_offset = f.tell()
                    break

        # Phase 2: detect and reassemble bit-exploded signals
        # bit-exploded: width==1, name has [N] suffix in the $var line
        bit_groups = defaultdict(dict)  # (scope, base_name) -> {bit_idx: symbol}
        bit_types = {}                   # (scope, base_name) -> vtype
        standalone = []

        for sym, name, w, bit_str, sc, vtype in raw_vars:
            if w == 1 and bit_str is not None:
                m = re.match(r'\[(\d+)\]', bit_str)
                if m:
                    idx = int(m.group(1))
                    bit_groups[(sc, name)][idx] = sym
                    bit_types[(sc, name)] = vtype
                    continue
            standalone.append((sym, name, w, sc, vtype))

        # Register standalone signals. Per IEEE 1364-2005 18.2.3.7, the same
        # identifier_code can be referenced under multiple paths (e.g. one
        # wire visible from multiple module scopes). Track all references.
        # When aliases have different var_types, the first encountered wins.
        for sym, name, w, sc, vtype in standalone:
            path = '{}.{}'.format(sc, name) if sc else name
            if sym in self.signals:
                self.signals[sym]['aliases'].append(path)
            else:
                self.signals[sym] = {
                    'path': path, 'width': w, 'type': vtype, 'aliases': [path]
                }

        # Register reassembled bit-exploded signals
        for (sc, name), bits in bit_groups.items():
            if not bits:
                continue
            max_bit = max(bits.keys())
            width = max_bit + 1
            path = '{}.{}[{}:0]'.format(sc, name, max_bit) if sc else '{}[{}:0]'.format(name, max_bit)
            sig_id = '__grp__{}__{}'.format(sc, name)
            self.signals[sig_id] = {
                'path': path, 'width': width,
                'type': bit_types.get((sc, name), 'wire'),
                'aliases': [path],
            }
            self._bit_state[sig_id] = ['x'] * width
            for idx, sym in bits.items():
                self._bit_map[sym] = (sig_id, idx)

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

    def iter_events(self, t0=0, t1=None, sids=None):
        """Yield (time, sig_id, value_str) with bit reassembly.

        Same-timestamp bit changes are buffered and emitted once per signal.
        """
        cur_t = -1
        pending = {}  # sig_id -> value_str (buffered for current timestamp)

        def _flush():
            if not pending:
                return []
            items = list(pending.items())
            pending.clear()
            return items

        with open(self.path, 'r', errors='replace') as f:
            f.seek(self._data_offset)
            for line in f:
                line = line.strip()
                if not line or line.startswith('$'):
                    continue

                if line[0] == '#':
                    new_t = int(line[1:])
                    # Flush previous timestamp
                    if cur_t >= t0:
                        for sid, val in _flush():
                            yield cur_t, sid, val
                    cur_t = new_t
                    if t1 is not None and cur_t > t1:
                        break
                    continue

                if cur_t < t0:
                    # Still parse to maintain bit state
                    if line[0] in '01xzXZ':
                        sym = line[1:]
                        if sym in self._bit_map:
                            gid, idx = self._bit_map[sym]
                            self._bit_state[gid][idx] = line[0].lower()
                    elif line[0] in 'bB':
                        pass  # multi-bit pre-range, skip
                    continue

                # Parse value
                if line[0] in '01xzXZ':
                    val, sym = line[0].lower(), line[1:]
                elif line[0] in 'bB':
                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        continue
                    val, sym = parts[0][1:].lower(), parts[1]
                elif line[0] in 'rR':
                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        continue
                    val, sym = parts[0][1:], parts[1]
                elif line[0] == 'p':
                    # Extended VCD port value (IEEE 1364-2005 18.4.3):
                    # p<state_char> <strength0> <strength1> <id>
                    # Map port state to 4-state value for analysis; strengths
                    # are discarded since they're rarely actionable for debug.
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    state = parts[0][1:] if len(parts[0]) > 1 else ''
                    val = _PORT_STATE.get(state, 'x')
                    sym = parts[3]
                else:
                    continue

                # Bit-exploded?
                if sym in self._bit_map:
                    gid, idx = self._bit_map[sym]
                    self._bit_state[gid][idx] = val
                    if sids is not None and gid not in sids:
                        continue
                    # Reconstruct: MSB first
                    bits = self._bit_state[gid]
                    pending[gid] = ''.join(reversed(bits))
                    continue

                # Standalone signal
                if sym not in self.signals:
                    continue
                if sids is not None and sym not in sids:
                    continue
                pending[sym] = val

            # Flush last timestamp
            if cur_t >= t0:
                for sid, val in _flush():
                    yield cur_t, sid, val

    def scan_time_range(self):
        """Quick scan for min/max timestamps."""
        t_min = t_max = None
        with open(self.path, 'r', errors='replace') as f:
            f.seek(self._data_offset)
            for line in f:
                if line[0] == '#':
                    t = int(line.strip()[1:])
                    if t_min is None:
                        t_min = t
                    t_max = t
        return t_min, t_max


# -- Subcommands -------------------------------------------------------------

def cmd_info(vcd, args):
    t_min, t_max = vcd.scan_time_range()
    ts = vcd.ts_sec
    # var_type distribution: count each $var declaration (i.e., each alias)
    type_counts = defaultdict(int)
    ref_count = 0
    for info in vcd.signals.values():
        n = len(info['aliases'])
        type_counts[info.get('type', 'wire')] += n
        ref_count += n
    r = {
        'file': vcd.path,
        'size_bytes': os.path.getsize(vcd.path),
        'timescale': vcd.ts_str.replace('$timescale', '').replace('$end', '').strip(),
        'signal_count': len(vcd.signals),
        'reference_count': ref_count,
        'var_types': dict(sorted(type_counts.items(), key=lambda x: -x[1])),
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
        else:
            print('Signals   : {} unique ({} references via aliases)'.format(
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
    sids = vcd.match(args.filter)
    stats = {}
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        if sid not in stats:
            stats[sid] = {'n': 0, 't0': t, 't1': t, 'v0': val, 'v1': val, 'uv': set()}
        s = stats[sid]
        s['n'] += 1
        s['t1'] = t
        s['v1'] = val
        s['uv'].add(val)

    rows = []
    for sid in sorted(stats, key=lambda s: vcd.signals[s]['path']):
        info, s = vcd.signals[sid], stats[sid]
        rows.append({
            'path': info['path'], 'width': info['width'], 'changes': s['n'],
            'unique': len(s['uv']),
            'first_at': fmt_time(s['t0'], ts), 'last_at': fmt_time(s['t1'], ts),
            'last_val': fmt_val(s['v1'], info),
        })
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    else:
        active = [r for r in rows if r['changes'] > 1]
        static = [r for r in rows if r['changes'] <= 1]
        if active:
            for r in active:
                print('  {:<45} w={:<4} chg={:<6} uniq={:<4} last@{:<12} = {}'.format(
                    r['path'], r['width'], r['changes'], r['unique'],
                    r['last_at'], r['last_val']))
        top = sorted(active, key=lambda x: x['changes'], reverse=True)[:5]
        if top:
            print('\nTop active:')
            for r in top:
                print('  {:<50} {} changes, {} unique values'.format(
                    r['path'], r['changes'], r['unique']))
        if static:
            print('\nStatic ({}):{}'.format(
                len(static),
                ' [use --json for full list]' if len(static) > 20 else ''))
            for r in static[:20]:
                print('  {:<55} = {}'.format(r['path'], r['last_val']))


def cmd_edges(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    sids = vcd.match(args.filter)
    prev = {}
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
            period = fmt_time(int(avg), ts)
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


def cmd_handshake(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    sids = vcd.match(args.filter)

    # Auto-discover AXI-Stream groups by tvalid/tready/tdata/tlast naming
    groups = defaultdict(dict)
    for sid, info in vcd.signals.items():
        if sids is not None and sid not in sids:
            continue
        name = info['path'].split('.')[-1].lower()
        # Strip bit range suffix like [511:0]
        base = re.sub(r'\[\d+:\d+\]$', '', name)
        for suffix, role in [('tvalid', 'valid'), ('tready', 'ready'),
                             ('tdata', 'data'), ('tlast', 'last')]:
            if base.endswith(suffix):
                prefix = info['path'][:-(len(name))] + base[:-(len(suffix))]
                groups[prefix][role] = sid
                break

    if not groups:
        print('No AXI-Stream signal groups found (need tvalid/tready naming)')
        return

    all_res = []
    for prefix, roles in sorted(groups.items()):
        if 'valid' not in roles or 'ready' not in roles:
            continue
        group_sids = set(roles.values())
        state = {}
        transfers = []
        # Buffer per-timestamp for correct same-cycle behavior
        pend_t, pend_chg, has_ctrl = None, {}, False

        def _check():
            for s, v in pend_chg.items():
                state[s] = v
            pend_chg.clear()
            v = state.get(roles['valid'], '0')
            r = state.get(roles['ready'], '0')
            if v == '1' and r == '1' and has_ctrl:
                xf = {'time': pend_t, 'time_h': fmt_time(pend_t, ts)}
                if 'data' in roles and roles['data'] in state:
                    dsid = roles['data']
                    xf['data'] = fmt_val(state[dsid], vcd.signals[dsid])
                if 'last' in roles and roles['last'] in state:
                    xf['last'] = state[roles['last']] == '1'
                transfers.append(xf)

        for t, sid, val in vcd.iter_events(t0, t1, group_sids):
            if t != pend_t:
                if pend_t is not None:
                    _check()
                pend_t, has_ctrl = t, False
            pend_chg[sid] = val
            if sid in (roles['valid'], roles['ready']):
                has_ctrl = True
        if pend_t is not None:
            _check()

        res = {
            'channel': prefix,
            'transfer_count': len(transfers),
            'transfers': transfers,
        }
        all_res.append(res)

    if args.json:
        print(json.dumps(all_res, indent=2, ensure_ascii=False))
    else:
        for r in all_res:
            print('\n=== {} ({} transfers) ==='.format(r['channel'], r['transfer_count']))
            for i, x in enumerate(r['transfers'][:200]):
                last = ' LAST' if x.get('last') else ''
                print('  {:>4}  {:<14}  {}{}'.format(i, x['time_h'], x.get('data', '-'), last))
            if len(r['transfers']) > 200:
                print('  ... {} total, showing first 200'.format(len(r['transfers'])))


def _build_snapshot(vcd, t_at, sids=None):
    """Replay from start to t_at, return {sig_id: value}."""
    state = {}
    for t, sid, val in vcd.iter_events(0, t_at, sids):
        state[sid] = val
    return state


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
        print('Snapshot @ {}'.format(fmt_time(t_at, ts)))
        for r in rows:
            print('  {:<55} = {}'.format(r['path'], r['value']))
        print('\n{} signals'.format(len(rows)))


def cmd_compare(vcd, args):
    ts = vcd.ts_sec
    parts = args.at.split(',')
    if len(parts) != 2:
        sys.exit('Error: --at needs two times separated by comma, e.g. --at 17.5us,17.7us')
    ta, tb = parse_time(parts[0].strip(), ts), parse_time(parts[1].strip(), ts)
    sids = vcd.match(args.filter)
    sa = _build_snapshot(vcd, ta, sids)
    # Continue from ta to tb for state_b
    sb = dict(sa)
    for t, sid, val in vcd.iter_events(ta, tb, sids):
        sb[sid] = val

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
    t1 = parse_time(args.end, ts) if args.end else None
    flt = [args.signal] if args.signal else args.filter
    sids = vcd.match(flt)
    target = args.value.lower().strip()
    matches = []
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        hit = (val == target)
        if not hit:
            iv = val_to_int(val)
            if iv is not None:
                try:
                    hit = iv == (int(target, 16) if target.startswith('0x') else int(target))
                except ValueError:
                    pass
        if hit:
            info = vcd.signals[sid]
            matches.append({'time': fmt_time(t, ts), 'path': info['path'],
                            'value': fmt_val(val, info)})
    if args.json:
        print(json.dumps(matches, indent=2, ensure_ascii=False))
    else:
        if not matches:
            print('No match for value "{}"'.format(args.value))
        else:
            print('Found {} matches for value "{}":'.format(len(matches), args.value))
            for m in matches[:200]:
                print('  {:<14} {:<50} = {}'.format(m['time'], m['path'], m['value']))
            if len(matches) > 200:
                print('  ... {} total'.format(len(matches)))


# -- CLI entry ---------------------------------------------------------------

def _add_time_args(sp):
    sp.add_argument('--begin', metavar='TIME',
                    help='start time, e.g. 0, 100ns, 17.5us (omit = from start)')
    sp.add_argument('--end', metavar='TIME',
                    help='end time, same format (omit = no upper bound)')

def _add_filter(sp):
    sp.add_argument('--filter', metavar='K1,K2,...', type=lambda s: s.split(','),
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

    sp = sub.add_parser('summary', help='per-signal stats: change count, unique values, static detection')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp)

    sp = sub.add_parser('edges', help='1-bit edge detection with frequency estimation')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp)

    sp = sub.add_parser('handshake', help='AXI-Stream valid&ready transfer analysis (auto-discovers tvalid/tready pairs)')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp)

    sp = sub.add_parser('snapshot', help='all signal values at a given time point')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='TIME', required=True, help='time point, e.g. 17.55us')
    _add_filter(sp)

    sp = sub.add_parser('compare', help='diff signal values between two time points')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='T1,T2', required=True, help='two time points comma-separated, e.g. 17.5us,17.7us')
    _add_filter(sp)

    sp = sub.add_parser('search', help='find when a signal equals a specific value')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp)
    sp.add_argument('--signal', metavar='KEYWORD', help='keyword to narrow which signals to search')
    sp.add_argument('--value', metavar='VAL', required=True,
                    help='target value: decimal (42), hex (0x2a), or binary (101010)')

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)

    vcd = VCDParser(args.file)
    cmds = {'info': cmd_info, 'list': cmd_list, 'dump': cmd_dump, 'summary': cmd_summary,
            'edges': cmd_edges, 'handshake': cmd_handshake, 'snapshot': cmd_snapshot,
            'compare': cmd_compare, 'search': cmd_search}
    cmds[args.cmd](vcd, args)


if __name__ == '__main__':
    main()
