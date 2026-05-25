import pytest
import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd, ns


def make_vcd(tmp_path):
    return write_vcd(tmp_path, minimal_vcd('''$var wire 1 ! clk $end
$var wire 1 " rst $end
$var wire 4 # state $end
''', '''$dumpvars
0!
1"
b0000 #
$end
#5
0"
#10
1!
b0011 #
#20
0!
'''))


def test_text_info_list_dump_summary_snapshot_compare_search(capsys, tmp_path):
    p = make_vcd(tmp_path)
    v = va.VCDParser(str(p))

    va.cmd_info(v, ns(verbose=True))
    out = capsys.readouterr().out
    assert 'File' in out and 'Timescale' in out and 'scope: tb' in out

    va.cmd_list(v, ns(filter=None, limit=2, verbose=True))
    out = capsys.readouterr().out
    assert 'Matched:' in out and 'truncated' in out

    va.cmd_dump(v, ns(begin='100ns', end='200ns'))
    assert '(no changes in range)' in capsys.readouterr().out

    va.cmd_dump(v, ns(begin='0ns', end='10ns', verbose=True, limit=0))
    out = capsys.readouterr().out
    assert 'T=0s' in out and 'w=' in out

    va.cmd_summary(v, ns(filter='clk,rst,state', verbose=True, limit=0))
    out = capsys.readouterr().out
    assert 'ACTIVE' in out and 'Selected:' in out

    va.cmd_snapshot(v, ns(at='10ns', filter='clk,state', verbose=True, limit=0))
    out = capsys.readouterr().out
    assert 'snapshot @ 10ns' in out and 'tb.state' in out

    va.cmd_compare(v, ns(at='10ns,20ns', filter='clk,state', verbose=True, limit=1))
    out = capsys.readouterr().out
    assert 'Compare:' in out and ('truncated' in out or 'changed' in out)

    va.cmd_search(v, ns(condition='clk=1', begin='100ns', end='200ns'))
    assert 'No interval' in capsys.readouterr().out

    va.cmd_search(v, ns(condition='rst=1', changed='clk', begin='20ns', end='20ns'))
    assert 'No event' in capsys.readouterr().out


def test_text_undefined_and_no_selected(capsys, tmp_path):
    p = write_vcd(tmp_path, minimal_vcd('$var wire 1 ! a $end\n$var wire 1 " never $end\n', '#0\n0!\n#1\n1!\n'))
    v = va.VCDParser(str(p))
    va.cmd_summary(v, ns(filter='does_not_exist'))
    assert '(no selected signals)' in capsys.readouterr().out
    va.cmd_summary(v, ns(filter='never', verbose=True))
    out = capsys.readouterr().out
    assert 'UNDEFINED' in out
    va.cmd_snapshot(v, ns(at='1ns', filter='never'))
    assert 'No known values' in capsys.readouterr().out


def test_main_version_and_error_paths(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', ['vcd_analyzer.py', '--version'])
    with pytest.raises(SystemExit) as e:
        va.main()
    assert e.value.code == 0
    assert 'vcd_analyzer' in capsys.readouterr().out

    monkeypatch.setattr('sys.argv', ['vcd_analyzer.py'])
    with pytest.raises(SystemExit):
        va.main()

def test_main_dispatches_common_commands(monkeypatch, capsys, tmp_path):
    p = make_vcd(tmp_path)
    for argv, expected in [
        (['vcd_analyzer.py','info',str(p)], 'Timescale'),
        (['vcd_analyzer.py','list',str(p),'--filter','clk'], 'tb.clk'),
        (['vcd_analyzer.py','dump',str(p),'--begin','0ns','--end','0ns'], 'T=0s'),
        (['vcd_analyzer.py','summary',str(p),'--filter','clk'], 'Selected:'),
        (['vcd_analyzer.py','snapshot',str(p),'--at','10ns','--filter','clk'], 'snapshot @ 10ns'),
        (['vcd_analyzer.py','compare',str(p),'--at','10ns,20ns','--filter','clk'], 'Compare:'),
        (['vcd_analyzer.py','search',str(p),'--condition','clk=1'], 'Found:'),
    ]:
        monkeypatch.setattr('sys.argv', argv)
        va.main()
        out = capsys.readouterr().out
        assert expected in out


def test_main_friendly_file_errors(monkeypatch, tmp_path):
    missing = tmp_path / 'missing.vcd'
    monkeypatch.setattr('sys.argv', ['vcd_analyzer.py','info',str(missing)])
    with pytest.raises(SystemExit) as e:
        va.main()
    assert 'cannot open VCD file' in str(e.value)

    monkeypatch.setattr('sys.argv', ['vcd_analyzer.py','info',str(tmp_path)])
    with pytest.raises(SystemExit) as e2:
        va.main()
    assert 'not a file' in str(e2.value)

    good = make_vcd(tmp_path)
    monkeypatch.setattr('sys.argv', ['vcd_analyzer.py','dump',str(good),'--begin','bad'])
    with pytest.raises(SystemExit) as e3:
        va.main()
    assert 'Error:' in str(e3.value)
