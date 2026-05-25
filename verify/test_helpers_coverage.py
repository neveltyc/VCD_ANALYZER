import math
import pytest
import vcd_analyzer as va


def test_time_parse_and_format_edges():
    assert va.parse_time('17.5ns', 1e-12) == 17500
    assert va.parse_time('.5us', 1e-9) == 500
    assert va.parse_time('-0ns', 1e-9) == 0
    with pytest.raises(va._TimeParseError):
        va.parse_time('5 ns', 1e-9)
    with pytest.raises(va._TimeParseError):
        va.parse_time('10.5', 1e-9)
    with pytest.raises(va._TimeParseError):
        va.parse_time('1ns', 0)
    assert va.fmt_time(0, 1e-9) == '0s'
    assert va.fmt_time(float('inf'), 1e-9) == '?'
    assert va.fmt_time(1, 0) == '?'


def test_safe_integer_and_timestamp_helpers():
    assert va._safe_int_digits('123') == 123
    assert va._safe_int_digits('') is None
    assert va._safe_int_digits('1' * 101) is None
    assert va._parse_vcd_timestamp_token('#12') == 12
    assert va._parse_vcd_timestamp_token('#1.5') is None
    with pytest.raises(va._VCDResourceError):
        va._parse_vcd_timestamp_token('#' + '1' * 101)


def test_value_parse_and_match_modes():
    assert va._parse_target_value('10') == ('10', 10)
    assert va._parse_target_value('0x0a') == ('0x0a', 10)
    assert va._parse_target_value('b1010') == ('1010', 10)
    assert va._parse_target_value('0b1x0') == ('1x0', None)
    with pytest.raises(va._ValueParseError):
        va._parse_target_value('0xfx')
    with pytest.raises(va._ValueParseError):
        va._parse_target_value('-1')
    with pytest.raises(va._ValueParseError):
        va._parse_target_value('')
    assert va._value_matches('00001010', '1010', 10, width=8)
    assert va._value_matches('0001x0', '1x0', None, width=6)
    assert not va._condition_match('x', '!=', '1', 1, width=1)
    assert va._condition_match('0', '!=', '1', 1, width=1)


def test_overwide_and_formatting():
    wire2 = {'width': 2, 'type': 'wire'}
    assert va._clamp_overwide_logic_value('11110', wire2) == 'xx'
    assert va.fmt_val('xx', wire2) == 'bxx'
    assert va.fmt_val('10', wire2) == '2 (0x2)'
    assert va.fmt_val('1', {'width': 1, 'type': 'wire'}) == '1'
    assert va.fmt_val('3.14', {'width': 64, 'type': 'real'}) == '3.14'
    assert va.fmt_val('1', {'width': 1, 'type': 'event'}) == 'triggered'
    assert va.val_to_int('10') == 2
    assert va.val_to_int('1x') is None


def test_filter_normalization_and_glob_lite():
    assert va._normalize_filter_patterns('**data[7:0],clk') == ['*data[7:0]', 'clk']
    with pytest.raises(va._FilterParseError):
        va._normalize_filter_patterns('x' * 300)
    with pytest.raises(va._FilterParseError):
        va._normalize_filter_patterns('a*' * 20)
    with pytest.raises(va._FilterParseError):
        va._normalize_filter_patterns(123)
    rx = va._glob_lite_regex('*data[7:0]')
    assert rx.match('tb.data[7:0]')
    assert not rx.match('tb.data7')
