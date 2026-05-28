import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "vcd_analyzer.py"
FIX_BASIC = ROOT / "verify" / "fixtures" / "basic_trace.vcd"
FIX_SEARCH = ROOT / "verify" / "fixtures" / "search_trace.vcd"
FIX_HANDSHAKE = ROOT / "verify" / "fixtures" / "handshake_trace.vcd"
FIX_BUS_RANGE = ROOT / "verify" / "fixtures" / "bus_range_trace.vcd"
FIX_ESCAPED = ROOT / "verify" / "fixtures" / "escaped_trace.vcd"

VERSION = "1.3.11"
LEGACY_SEARCH = False
SUPPORTS_EDGES = False
SUPPORTS_HANDSHAKE = False
SEARCH_T0_MAY_COUNT = False
SUPPORTS_LIMIT_VERBOSE = True
DUMP_JSON_SUPPORTED = True
SUPPORTS_GLOB_LITE = True
SUPPORTS_SCOPE_FIX = True


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, args)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )


def run_json(*args):
    result = run_cli(*args)
    if result.returncode != 0:
        raise AssertionError(
            "command failed\nSTDOUT={}\nSTDERR={}".format(result.stdout, result.stderr)
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            "invalid JSON\nSTDOUT={}\nSTDERR={}".format(result.stdout, result.stderr)
        ) from exc


def extract_rows(obj, key):
    if isinstance(obj, list):
        return obj
    return obj.get(key, [])

def expect_ok(*args):
    result = run_cli(*args)
    if result.returncode != 0:
        raise AssertionError(
            "command failed\nARGS={}\nSTDOUT={}\nSTDERR={}".format(args, result.stdout, result.stderr)
        )
    return result


class TestCLI(unittest.TestCase):
    def test_version_banner(self):
        result = expect_ok("--version")
        self.assertIn(VERSION, result.stdout)

    def test_info_and_list(self):
        info = run_json("--json", "info", FIX_BASIC)
        self.assertEqual(info["signal_count"], 5)
        self.assertIn("tb", info.get("scopes", []))

        listed = run_json("--json", "list", FIX_BASIC, "--filter", "state,data")
        rows = extract_rows(listed, "signals")
        paths = sorted(r["path"] for r in rows)
        self.assertEqual(paths, ["tb.data", "tb.state"])

    def test_dump_window(self):
        args = ("dump", FIX_BASIC, "--begin", "10ns", "--end", "20ns", "--filter", "state,data")
        if DUMP_JSON_SUPPORTED:
            dumped = run_json("--json", *args)
            rows = extract_rows(dumped, "events")
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(r["path"] in {"tb.state", "tb.data"} for r in rows))
        else:
            result = expect_ok("--json", *args)
            self.assertIn("tb.state", result.stdout)
            self.assertIn("tb.data", result.stdout)
            self.assertIn("3 changes", result.stdout)

    def test_snapshot_and_compare(self):
        snap = run_json("--json", "snapshot", FIX_BASIC, "--at", "20ns", "--filter", "state,data")
        rows = extract_rows(snap, "signals")
        values = {row["path"]: row["value"] for row in rows}
        self.assertEqual(values["tb.state"], "2 (0x2)")
        self.assertEqual(values["tb.data"], "17 (0x11)")

        diff = run_json("--json", "compare", FIX_BASIC, "--at", "10ns,30ns", "--filter", "state,data")
        rows = extract_rows(diff, "diffs")
        self.assertEqual(sorted(r["path"] for r in rows), ["tb.data", "tb.state"])

    def test_summary(self):
        summary = run_json("--json", "summary", FIX_BASIC, "--begin", "0ns", "--end", "30ns", "--filter", "state,data")
        rows = extract_rows(summary, "rows")
        self.assertTrue(any(r["path"] == "tb.state" for r in rows))

    def test_limit_and_verbose_when_supported(self):
        if not SUPPORTS_LIMIT_VERBOSE:
            return
        dumped = run_json("dump", FIX_BASIC, "--begin", "0ns", "--end", "30ns", "--filter", "clk,state,data", "--json", "--limit", "1")
        rows = extract_rows(dumped, "events")
        self.assertEqual(len(rows), 1)
        self.assertTrue(dumped.get("truncated"))

        result = expect_ok("summary", FIX_BASIC, "--begin", "0ns", "--end", "30ns", "--filter", "state,data", "--verbose")
        self.assertIn("tb.state", result.stdout)
        self.assertIn("w=", result.stdout)

    def test_search(self):
        if LEGACY_SEARCH:
            data = run_json(
                "--json",
                "search",
                FIX_BASIC,
                "--signal",
                "state",
                "--value",
                "2",
                "--begin",
                "10ns",
                "--end",
                "30ns",
                "--filter",
                "state,data",
            )
            if isinstance(data, list):
                self.assertEqual(len(data), 1)
                self.assertEqual(data[0]["path"], "tb.state")
                self.assertEqual(data[0]["value"], "2 (0x2)")
            else:
                matches = data["matches"]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0]["path"], "tb.state")
                self.assertEqual(matches[0]["value"], "2 (0x2)")
        else:
            seg = run_json(
                "--json",
                "search",
                FIX_SEARCH,
                "--condition",
                "tb.valid=1,tb.ready=1",
                "--show",
                "tb.data",
                "--begin",
                "0ns",
                "--end",
                "100ns",
            )
            key = "segments" if "segments" in seg else "intervals"
            rows = seg[key]
            self.assertEqual([(r["begin_ticks"], r["end_ticks"]) for r in rows], [(20, 25), (25, 30)])

            changed = run_json(
                "--json",
                "search",
                FIX_SEARCH,
                "--changed",
                "tap",
                "--condition",
                "tb.valid=0",
                "--begin",
                "0ns",
                "--end",
                "100ns",
            )
            times = [row["time_ticks"] for row in changed["events"]]
            if SEARCH_T0_MAY_COUNT:
                self.assertEqual(times, [0, 40, 60])
            else:
                self.assertEqual(times, [40, 60])

    def test_optional_commands(self):
        if SUPPORTS_EDGES:
            edges = run_json("--json", "edges", FIX_BASIC, "--begin", "0ns", "--end", "30ns", "--filter", "clk")
            rows = extract_rows(edges, "rows")
            if not rows:
                rows = edges
            self.assertEqual(rows[0]["path"], "tb.clk")

        if SUPPORTS_HANDSHAKE:
            hs = run_json("--json", "handshake", FIX_HANDSHAKE, "--begin", "0ns", "--end", "30ns", "--filter", "lane")
            rows = extract_rows(hs, "rows")
            if not rows:
                rows = hs
            self.assertEqual(rows[0]["transfer_count"], 2)

    def test_latest_regressions(self):
        if SUPPORTS_GLOB_LITE:
            listed = run_json("--json", "list", FIX_BUS_RANGE, "--filter", "*data[7:0]")
            rows = extract_rows(listed, "signals")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["path"], "tb.data[7:0]")

        if SUPPORTS_SCOPE_FIX:
            info = run_json("--json", "info", FIX_ESCAPED)
            self.assertEqual(info["scopes"], ["tb"])


    def test_filter_normalize_rejects_non_sequence(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("vcd_analyzer_testmod", str(SCRIPT))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with self.assertRaises(mod._FilterParseError):
            mod._normalize_filter_patterns(123)

    def test_compare_rejects_reversed_time_range(self):
        result = run_cli("compare", FIX_BASIC, "--at", "30ns,10ns")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("second compare time must be >= first compare time", result.stderr)

    def test_search_rejects_empty_data_section(self):
        empty_vcd = """\
$timescale 1ns $end
$scope module tb $end
$var wire 1 ! sig $end
$upscope $end
$enddefinitions $end
"""
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".vcd", delete=False) as f:
            f.write(empty_vcd)
            tmp = f.name
        try:
            result = run_cli("search", tmp, "--condition", "sig=1")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contains no value changes", result.stderr)
            result_json = run_cli("--json", "search", tmp, "--condition", "sig=1")
            self.assertNotEqual(result_json.returncode, 0)
            self.assertIn("contains no value changes", result_json.stderr)
        finally:
            os.unlink(tmp)


    def _base_vcd(self, decls, data):
        return "$timescale 1ns $end\n$scope module tb $end\n" + decls + "$upscope $end\n$enddefinitions $end\n" + data

    def _tmp_vcd(self, body):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".vcd", delete=False) as f:
            f.write(body)
            return f.name

    def test_info_dump_agree_on_malformed_vector(self):
        tmp = self._tmp_vcd(self._base_vcd('$var wire 1 ! a $end\n', 'b1010\n#10\n1!\n'))
        try:
            info = run_json("--json", "info", tmp)
            dump = run_json("--json", "dump", tmp)
            self.assertEqual(info["time_max_ticks"], 10)
            self.assertEqual([e["time_ticks"] for e in dump["events"]], [10])
        finally:
            import os; os.unlink(tmp)

    def test_info_dump_agree_on_malformed_real(self):
        decls = '$var real 64 ! r $end\n$var wire 1 " a $end\n'
        data = 'reset !\n#7\n1"\n'
        tmp = self._tmp_vcd(self._base_vcd(decls, data))
        try:
            info = run_json("--json", "info", tmp)
            dump = run_json("--json", "dump", tmp)
            self.assertEqual(info["time_max_ticks"], 7)
            self.assertEqual(dump["events"][0]["time_ticks"], 7)
        finally:
            import os; os.unlink(tmp)

    def test_info_dump_agree_on_malformed_port(self):
        tmp = self._tmp_vcd(self._base_vcd('$var wire 1 ! p $end\n', 'pH #10 1!\n#20\n0!\n'))
        try:
            info = run_json("--json", "info", tmp)
            dump = run_json("--json", "dump", tmp)
            self.assertEqual(info["time_max_ticks"], 20)
            self.assertEqual([e["time_ticks"] for e in dump["events"]], [10, 20])
        finally:
            import os; os.unlink(tmp)

    def test_valid_multichar_port_parses_both_info_and_dump(self):
        tmp = self._tmp_vcd(self._base_vcd('$var wire 2 ! data $end\n', '#0\npHL 0 6 !\n'))
        try:
            info = run_json("--json", "info", tmp)
            dump = run_json("--json", "dump", tmp)
            self.assertEqual(info["time_min_ticks"], 0)
            self.assertEqual(dump["events"][0]["value"], "2 (0x2)")
        finally:
            import os; os.unlink(tmp)


if __name__ == "__main__":
    unittest.main()
