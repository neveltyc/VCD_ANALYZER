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
    # Section bodies ($comment/$bogus/$vcdclose) must not leak their tokens
    # into the event stream or the time range: #999, the bogus-body 1!, and
    # the $vcdclose final-time record are all section content, not top-level
    # timestamps or events.
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


def test_iter_events_filter_fast_path_keeps_selected_vector_and_real(tmp_path):
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 8 ! keep_vec $end\n"
            "$var wire 8 \" skip_vec $end\n"
            "$var real 64 # keep_real $end\n"
            "$var real 64 $ skip_real $end\n",
            "#0\n"
            "b00000001 !\n"
            "b00000010 \"\n"
            "r1.5 #\n"
            "r2.5 $\n"
            "#10\n"
            "b00000011 !\n"
            "r3.5 #\n"
            "b00000100 \"\n",
        ),
    )
    v = va.VCDParser(str(p))
    sids = v.match("keep_vec,keep_real")
    events = [(t, v.signals[sid]["path"], val) for t, sid, val in v.iter_events(0, None, sids)]
    assert events == [
        (0, "tb.keep_vec", "00000001"),
        (0, "tb.keep_real", "1.5"),
        (10, "tb.keep_vec", "00000011"),
        (10, "tb.keep_real", "3.5"),
    ]


def test_iter_events_filter_fast_path_keeps_synthesized_bus_updates(tmp_path):
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 1 ! bus [0] $end\n"
            "$var wire 1 \" bus [1] $end\n"
            "$var wire 1 # other $end\n",
            "#0\n"
            "0!\n"
            "1\"\n"
            "0#\n"
            "#10\n"
            "1!\n"
            "1#\n",
        ),
    )
    v = va.VCDParser(str(p))
    sids = v.match("bus[1:0]")
    events = [(t, v.signals[sid]["path"], val) for t, sid, val in v.iter_events(0, None, sids)]
    # The bus is not a declared signal: bits arrive independently, so each bit
    # update emits the current assembled value (unknown bits stay 'x') until
    # all bits are known.
    assert events == [
        (0, "tb.bus[1:0]", "x0"),
        (0, "tb.bus[1:0]", "10"),
        (10, "tb.bus[1:0]", "11"),
    ]


def test_scan_time_range_handles_initial_dumpvars_without_leading_timestamp(tmp_path):
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 1 ! sig $end\n",
            "$dumpvars\n"
            "1!\n"
            "$end\n"
            "#10\n"
            "0!\n",
        ),
    )
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (0, 10)


def test_scan_time_range_handles_initial_dumpvars_only(tmp_path):
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 1 ! sig $end\n",
            "$dumpvars\n"
            "1!\n"
            "$end\n",
        ),
    )
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (0, 0)


def test_scan_time_range_tolerates_indented_timestamps(tmp_path):
    # VCD is a free-format token stream: leading whitespace before a #T
    # timestamp is legal.  The backward t_max scan must not collapse to t_min
    # (which produced e.g. 500ns ~ 500ns for indented dumps).
    text = minimal_vcd("$var wire 1 ! sig $end\n", "#0\n1!\n#100\n0!\n")
    indented = "".join("    " + line + "\n" for line in text.splitlines())
    p = write_vcd(tmp_path, indented, name="indented.vcd")
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (0, 100)


def test_scan_time_range_finds_last_timestamp_in_large_tail(tmp_path):
    body = ["#0", "0!"]
    for i in range(1, 6000):
        body.append(f"#{i}")
        body.append("1!" if i % 2 else "0!")
    p = write_vcd(
        tmp_path,
        minimal_vcd("$var wire 1 ! sig $end\n", "\n".join(body) + "\n"),
    )
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (0, 5999)


def test_iter_events_preserves_intra_timestamp_transitions(tmp_path):
    # IEEE 1364 allows several value_changes to the same identifier within one
    # simulation_time (delta-cycle style writers). Every change is emitted;
    # only consecutive identical runs coalesce.
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n',
        '#10\n0!\n1!\n0!\n#20\n1!\n'))
    v = va.VCDParser(str(p))
    assert list(v.iter_events(0, None, None)) == [
        (10, '!', '0'), (10, '!', '1'), (10, '!', '0'), (20, '!', '1')]


def test_iter_events_coalesces_consecutive_duplicate_runs(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n',
        '#10\n1!\n1!\n0!\n'))
    v = va.VCDParser(str(p))
    assert list(v.iter_events(0, None, None)) == [
        (10, '!', '1'), (10, '!', '0')]


def test_iter_events_dumpall_checkpoint_not_emitted(tmp_path):
    # $dumpall/$dumpon re-emit current values; a redundant same-value record
    # is a no-op, not a change (keeps static signals static in summary).
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! a $end\n$var wire 1 " b $end\n',
        '#0\n1!\n0"\n#5\n$dumpall\n1!\n0"\n$end\n#10\n0!\n'))
    v = va.VCDParser(str(p))
    events = list(v.iter_events(0, None, None))
    assert (5, '!', '1') not in events
    assert (5, '"', '0') not in events
    assert (10, '!', '0') in events


def test_iter_events_bit_bus_intra_timestamp(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! bus [0] $end\n$var wire 1 " bus [1] $end\n',
        '#10\n1!\n0"\n1!\n'))
    v = va.VCDParser(str(p))
    events = list(v.iter_events(0, None, None))
    bus = [val for _t, sid, val in events if sid.startswith('__grp__')]
    # bit0=1 -> 'x1'; bit1=0 -> '01'; bit0=1 again (same value, coalesced)
    assert bus == ['x1', '01']
    # Bit-select $var declarations are consumed by the synthesized bus, so no
    # separate standalone events exist for the raw bits (pre-1.3.20 behavior).
    assert not any(not sid.startswith('__grp__') for _t, sid, _val in events)


def test_scan_time_range_tail_value_changes_beyond_window(tmp_path):
    # IEEE 1364 places no bound on the number of value_changes after the final
    # timestamp; a trailing same-timestamp region larger than the scan window
    # must not collapse t_max to t_min.
    p = write_vcd(
        tmp_path,
        "$timescale 1ns $end\n"
        "$var wire 1 a clk $end\n"
        "$enddefinitions $end\n"
        "#0\n0a\n#100\n",
        'bigtail.vcd',
    )
    with open(p, 'a', newline='\n') as f:
        f.write('1a\n0a\n' * 2100000)  # ~8 MiB after the last #T
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (0, 100)


def test_scan_time_range_trailing_comment_excludes_body_timestamps(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! clk $end\n',
        '#0\n0!\n#42\n1!\n$comment tail #999 note $end\n'))
    v = va.VCDParser(str(p))
    # #999 inside the $comment body is not a timestamp
    assert v.scan_time_range() == (0, 42)


def test_scan_time_range_trailing_vcdclose(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! clk $end\n',
        '#0\n0!\n#42\n1!\n$vcdclose #999 $end\n'))
    v = va.VCDParser(str(p))
    # $vcdclose is a section like any other: its body (including the final
    # simulation time record) is not top level, so t_max stays at the last
    # real timestamp — matching the forward parser and iter_events().
    assert v.scan_time_range() == (0, 42)


def test_scan_time_range_plain_tail(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! clk $end\n',
        '#0\n0!\n#500\n1!\n#700\n0!\n'))
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (0, 700)


def test_scan_time_range_last_timestamp_after_large_region_free_run(tmp_path):
    # An ordinary value_change run (no $sections) larger than the scan window
    # sits BEFORE the last timestamp: #0, >4 MiB of changes, then #100 near
    # EOF. The reverse tail scan must start each window's region state from the
    # top level carried out of EOF; the earlier code instead assumed any window
    # not reaching the data start opened *inside* a skip region, so it skipped
    # the whole first window and reported the earlier #0 as t_max.
    p = write_vcd(
        tmp_path,
        "$timescale 1ns $end\n$var wire 1 ! s $end\n$enddefinitions $end\n"
        "#0\n0!\n",
        'deeptail.vcd',
    )
    with open(p, 'a', newline='\n') as f:
        f.write('1!\n0!\n' * 800000)   # ~4.6 MiB of ordinary value changes
        f.write('#100\n1!\n0!\n')
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (0, 100)


def test_scan_time_range_trailing_dumpall(tmp_path):
    # $dumpall/$dumpon/$dumpvars ARE $kw..$end sections. Walked in reverse the
    # closing $end enters a region that the opening $dumpall must EXIT; treating
    # the dump keyword as a bare marker leaks the skip backward over the real
    # last timestamp.
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n',
        '#10\n1!\n#42\n$dumpall\n1!\n$end\n'))
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (10, 42)


def test_scan_time_range_trailing_dumpon(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! s $end\n',
        '#10\n1!\n#42\n$dumpon\n1!\n$end\n'))
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (10, 42)


def test_scan_time_range_timestamp_split_across_window_boundary(tmp_path):
    # A fixed-size tail read can cut a '#<digits>' token at the window edge.
    # The low fragment must be stitched onto the next (lower) window, or a
    # truncated '#12345...' is misread as a smaller but still-valid timestamp.
    window = 4 * 1024 * 1024
    prefix = ("$timescale 1ns $end\n$var wire 1 ! s $end\n"
              "$enddefinitions $end\n#500\n0!\n")
    big = "#123456789\n"          # 11 bytes; the true last timestamp
    # Land the split 5 bytes into `big` so the boundary cuts "#1234" | "56789":
    #   split = file_size - window must equal len(prefix) + 5
    #   file_size = len(prefix) + len(big) + len(tail)  =>  len(tail) = window - 6
    tail_len = window - (len(big) - 5)
    unit = "1!\n0!\n"
    tail = unit * (tail_len // len(unit))
    tail += " " * (tail_len - len(tail))   # whitespace pad to the exact length
    p = tmp_path / "split.vcd"
    with open(p, "w", newline="\n") as f:
        f.write(prefix)
        f.write(big)
        f.write(tail)
    v = va.VCDParser(str(p))
    assert v.scan_time_range() == (500, 123456789)
