import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd


def _row_by_path(rows, path):
    return next(r for r in rows if r["path"] == path)


def test_summary_counts_begin_boundary_scalar_rise(tmp_path):
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 1 ! sig $end\n",
            "#0\n0!\n#10\n1!\n#20\n0!\n",
        ),
    )
    v = va.VCDParser(str(p))
    rows, _undef, counts = va._summary_rows(v, 10, 20, None)
    row = _row_by_path(rows, "tb.sig")
    assert counts["active"] == 1
    assert row["changes"] == 2
    assert row["rise_count"] == 1
    assert row["fall_count"] == 1
    assert row["first_at_ticks"] == 10
    assert row["last_at_ticks"] == 20


def test_summary_counts_begin_boundary_scalar_fall(tmp_path):
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 1 ! sig $end\n",
            "#0\n1!\n#10\n0!\n#20\n1!\n",
        ),
    )
    v = va.VCDParser(str(p))
    rows, _undef, counts = va._summary_rows(v, 10, 20, None)
    row = _row_by_path(rows, "tb.sig")
    assert counts["active"] == 1
    assert row["changes"] == 2
    assert row["rise_count"] == 1
    assert row["fall_count"] == 1
    assert row["first_at_ticks"] == 10
    assert row["last_at_ticks"] == 20


def test_summary_begin_zero_excludes_initialization_from_changes(tmp_path):
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 1 ! sig $end\n",
            "$dumpvars\n1!\n$end\n#10\n0!\n",
        ),
    )
    v = va.VCDParser(str(p))
    rows, _undef, counts = va._summary_rows(v, 0, 10, None)
    row = _row_by_path(rows, "tb.sig")
    assert counts["active"] == 1
    assert row["changes"] == 1
    assert row["rise_count"] == 0
    assert row["fall_count"] == 1
    assert row["first_at_ticks"] == 10
    assert row["last_at_ticks"] == 10
    assert row["init"] == "1"
    assert row["last"] == "0"


def test_summary_begin_boundary_vector_updates_first_last_unique(tmp_path):
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 2 ! vec $end\n",
            "#0\nb00 !\n#10\nb01 !\n#20\nb10 !\n",
        ),
    )
    v = va.VCDParser(str(p))
    rows, _undef, _counts = va._summary_rows(v, 10, 20, None)
    row = _row_by_path(rows, "tb.vec")
    assert row["changes"] == 2
    assert row["first_at_ticks"] == 10
    assert row["last_at_ticks"] == 20
    assert row["last"] == "2 (0x2)"
    assert row["unique"] == 3
    assert row["init"] == "0 (0x0)"


def test_dump_and_summary_agree_begin_boundary_is_in_window(tmp_path):
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 1 ! sig $end\n",
            "#0\n0!\n#10\n1!\n#20\n0!\n",
        ),
    )
    v = va.VCDParser(str(p))
    dump_events = list(v.iter_events(10, 20, None))
    rows, _undef, _counts = va._summary_rows(v, 10, 20, None)
    row = _row_by_path(rows, "tb.sig")
    assert [t for t, _sid, _val in dump_events] == [10, 20]
    assert row["changes"] == 2


def test_summary_begin_zero_init_only_signal_is_static(tmp_path):
    """t=0 initialization dump is baseline, not a change, for --begin 0."""
    p = write_vcd(
        tmp_path,
        minimal_vcd(
            "$var wire 1 ! sig $end\n$var wire 1 \" other $end\n",
            "#0\n0!\n0\"\n#100\n1\"\n",
        ),
    )
    v = va.VCDParser(str(p))
    rows, _undef, counts = va._summary_rows(v, 0, None, None)
    sig = _row_by_path(rows, "tb.sig")
    assert sig["kind"] == "static"
    assert sig["changes"] == 0
    assert sig["init"] == "0"
    assert sig["last"] == "0"
    assert sig["rise_count"] == 0
    assert sig["fall_count"] == 0
    other = _row_by_path(rows, "tb.other")
    assert other["kind"] == "active"
    assert other["changes"] == 1
    assert other["init"] == "0"
    assert counts["active"] == 1
    assert counts["static"] == 1

