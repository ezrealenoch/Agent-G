"""`agent-g drive` argument parsing.

Regression: the `drive` parser re-declared `binary`/`--port`/`--ready-timeout`/`--detach`/`--force` so that the bare
form `agent-g drive <binary>` would work. argparse applies a parent parser's defaults AFTER the subparser has parsed,
so `drive start <binary> --detach` came back with binary=None, detach=False ("drive requires a binary path"), and
the bare form never parsed at all (the path was read as an invalid subcommand choice).
"""
from src.cli import _build_parser, _normalize_drive_argv


def _parse(argv):
    return _build_parser().parse_args(_normalize_drive_argv(argv))


def test_explicit_start_keeps_binary_and_flags():
    a = _parse(["drive", "start", "/tmp/x.bin", "--detach", "--port", "19005", "--ready-timeout", "30"])
    assert (a.drive_action, a.binary, a.detach, a.port, a.ready_timeout) == ("start", "/tmp/x.bin", True, 19005, 30.0)


def test_bare_form_is_start():
    a = _parse(["drive", "/tmp/x.bin", "--detach"])
    assert (a.drive_action, a.binary, a.detach) == ("start", "/tmp/x.bin", True)


def test_stop_and_status_still_parse():
    assert _parse(["drive", "stop", "--force"]).force is True
    assert _parse(["drive", "status"]).drive_action == "status"


def test_other_commands_untouched():
    assert _normalize_drive_argv(["analyze", "/tmp/x.bin"]) == ["analyze", "/tmp/x.bin"]
    assert _normalize_drive_argv(["drive", "--help"]) == ["drive", "--help"]
    assert _normalize_drive_argv([]) == []
