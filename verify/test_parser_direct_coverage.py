import pytest
import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd


def test_header_metadata_scopes_aliases_and_bus_range(tmp_path):
    vcd_text = '''$date today $end
$version test-sim $end
$timescale 1ns $end
$comment hello world $end
$scope module tb $end
$var wire 1 ! \\foo.bar $end
$var wire 1 " data [0:0] $end
$upscope $end
$enddefinitions $end
#0
0!
1"
'''
    p = write_vcd(tmp_path, vcd_text)
    v = va.VCDParser(str(p))
    assert v.date == 'today'
    assert v.version == 'test-sim'
    assert v.comments == ['hello world']
    assert any(info['path'].endswith('data[0:0]') for info in v.signals.values())
    assert sorted(set(sc for info in v.signals.values() for sc in info.get('scopes', []))) == ['tb']


def test_bit_exploded_reassembly_and_duplicate_index_fallback(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! bus [0] $end\n$var wire 1 " bus [1] $end\n',
        '#0\n0!\n1"\n#5\n1!\n'))
    v = va.VCDParser(str(p))
    assert any(info.get('synthesized') and info['width'] == 2 for info in v.signals.values())
    vals = list(v.iter_events(0, None, None))
    assert any(val in ('10', '11') for _t, _sid, val in vals)

    p2 = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! dup [0] $end\n$var wire 1 " dup [0] $end\n$var wire 1 # dup [1] $end\n',
        '#0\n0!\n1"\n1#\n'), 'dup.vcd')
    v2 = va.VCDParser(str(p2))
    assert not any(info.get('synthesized') and 'dup' in info['path'] for info in v2.signals.values())
    assert sum(1 for info in v2.signals.values() if 'dup' in info['path']) == 3


def test_identifier_code_starting_with_hash_disambiguated(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd('$var wire 1 #1 hsig $end\n$var wire 1 ! a $end\n', '#0\n1#1\n#5\n0#1\n1!\n'))
    v = va.VCDParser(str(p))
    events = list(v.iter_events(0, None, None))
    hsid = next(sid for sid, info in v.signals.items() if info['path'].endswith('hsig'))
    assert [(t, val) for t, sid, val in events if sid == hsid] == [(0, '1'), (5, '0')]


def test_keywords_and_vcdclose_do_not_pollute(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd('$var wire 1 ! a $end\n', '$comment #999 1! $end\n$bogus 1! $end\n#3\n1!\n$vcdclose #100 $end\n'))
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (3, 3)
    assert [(t, val) for t, _sid, val in v.iter_events()] == [(3, '1')]


def test_extended_ports_valid_invalid_and_overwide(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd('$var wire 2 ! data $end\n$var wire 1 " flag $end\n', '#0\npHL 0 6 !\npQ 0 6 "\n#10\n1"\n#20\npHHHHL 0 6 !\n'))
    v = va.VCDParser(str(p))
    events = [(t, v.signals[sid]['path'], val, va.fmt_val(val, v.signals[sid])) for t, sid, val in v.iter_events()]
    assert (0, 'tb.data', '10', '2 (0x2)') in events
    assert (10, 'tb.flag', '1', '1') in events
    assert any(t == 20 and path == 'tb.data' and val == 'xx' for t, path, val, _fmt in events)


def test_resource_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(va, 'MAX_VARS', 1)
    p = write_vcd(tmp_path, minimal_vcd('$var wire 1 ! a $end\n$var wire 1 " b $end\n', '#0\n0!\n'))
    with pytest.raises(va._VCDResourceError):
        va.VCDParser(str(p))

    monkeypatch.setattr(va, 'MAX_VARS', 1000)
    monkeypatch.setattr(va, 'MAX_INITIAL_TOKENS', 2)
    p2 = write_vcd(tmp_path, '$timescale 1ns $end\n$scope module tb $end\n$var wire 1 ! a $end\n$upscope $end\n$enddefinitions $end #0 0! #1 1!\n')
    with pytest.raises(va._VCDResourceError):
        va.VCDParser(str(p2))
