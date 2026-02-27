"""Tests for pure functions in server.py."""
import sys
from pathlib import Path

import pytest

# Add project root to path so we can import server
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import (
    HostConfig,
    HostShell,
    HostStatus,
    _format_result,
    _is_transient_failure,
    _orchestra_truncate,
    _ps_quote,
    _resolve_host,
    _wrap_command,
    HOSTS,
    MAX_INLINE_OUTPUT,
)


# ---------------------------------------------------------------------------
# _ps_quote
# ---------------------------------------------------------------------------

class TestPsQuote:
    def test_simple_path(self):
        assert _ps_quote("C:\\Users\\foo") == '"C:\\Users\\foo"'

    def test_path_with_spaces(self):
        assert _ps_quote("C:\\My Documents\\file.txt") == '"C:\\My Documents\\file.txt"'

    def test_escapes_backtick(self):
        assert _ps_quote("foo`bar") == '"foo``bar"'

    def test_escapes_dollar(self):
        assert _ps_quote("$HOME") == '"`$HOME"'

    def test_escapes_double_quote(self):
        assert _ps_quote('say "hello"') == '"say `"hello`""'

    def test_combined_special_chars(self):
        result = _ps_quote('$env:`path "x"')
        assert result == '"`$env:``path `"x`""'

    def test_empty_string(self):
        assert _ps_quote("") == '""'


# ---------------------------------------------------------------------------
# _resolve_host
# ---------------------------------------------------------------------------

class TestResolveHost:
    def test_known_host(self):
        # Use the first host from the loaded config
        name = next(iter(HOSTS))
        config = _resolve_host(name)
        assert isinstance(config, HostConfig)
        assert config.alias  # has a non-empty alias

    def test_unknown_host_raises(self):
        with pytest.raises(ValueError, match="Unknown host"):
            _resolve_host("nonexistent-host-that-does-not-exist")

    def test_error_lists_available_hosts(self):
        with pytest.raises(ValueError) as exc_info:
            _resolve_host("bogus")
        for name in HOSTS:
            assert name in str(exc_info.value)


# ---------------------------------------------------------------------------
# _wrap_command
# ---------------------------------------------------------------------------

class TestWrapCommand:
    def _make_config(self, shell=HostShell.BASH, is_local=False):
        return HostConfig(
            alias="test-alias",
            display_name="test",
            description="test host",
            shell=shell,
            is_local=is_local,
        )

    def test_bash_simple(self):
        config = self._make_config()
        assert _wrap_command(config, "ls -la", None, False) == "ls -la"

    def test_bash_with_cwd(self):
        config = self._make_config()
        result = _wrap_command(config, "ls", "/tmp/test dir", False)
        assert result.startswith("cd ")
        assert "&&" in result
        assert "ls" in result

    def test_bash_with_sudo(self):
        config = self._make_config()
        result = _wrap_command(config, "ls", None, True)
        assert result == "sudo ls"

    def test_bash_with_cwd_and_sudo(self):
        config = self._make_config()
        result = _wrap_command(config, "ls", "/tmp", True)
        assert "cd" in result
        assert "sudo" in result

    def test_powershell_simple(self):
        config = self._make_config(shell=HostShell.POWERSHELL)
        assert _wrap_command(config, "Get-Process", None, False) == "Get-Process"

    def test_powershell_with_cwd(self):
        config = self._make_config(shell=HostShell.POWERSHELL)
        result = _wrap_command(config, "dir", "C:\\Users", False)
        assert "Set-Location" in result
        assert "-LiteralPath" in result
        assert "dir" in result

    def test_powershell_with_cwd_uses_ps_quote(self):
        config = self._make_config(shell=HostShell.POWERSHELL)
        result = _wrap_command(config, "dir", "C:\\$pecial", False)
        # Should use _ps_quote which escapes $
        assert "`$pecial" in result


# ---------------------------------------------------------------------------
# _is_transient_failure
# ---------------------------------------------------------------------------

class TestIsTransientFailure:
    def test_connection_refused(self):
        assert _is_transient_failure(255, "Connection refused")

    def test_connection_timed_out(self):
        assert _is_transient_failure(255, "Connection timed out")

    def test_broken_pipe(self):
        assert _is_transient_failure(-1, "Broken pipe")

    def test_mux_client_failure(self):
        assert _is_transient_failure(255, "mux_client_request_session: session request failed")

    def test_non_transient_rc(self):
        # rc=1 is not a transient SSH failure
        assert not _is_transient_failure(1, "Connection refused")

    def test_non_transient_message(self):
        assert not _is_transient_failure(255, "Permission denied (publickey)")

    def test_success_not_transient(self):
        assert not _is_transient_failure(0, "")


# ---------------------------------------------------------------------------
# _format_result
# ---------------------------------------------------------------------------

class TestFormatResult:
    def test_stdout_only(self):
        result = _format_result("hello", "", 0)
        assert result == "hello"

    def test_stderr_only(self):
        result = _format_result("", "error msg", 0)
        assert "[stderr]" in result
        assert "error msg" in result

    def test_both_stdout_stderr(self):
        result = _format_result("out", "err", 0)
        assert "out" in result
        assert "[stderr]" in result
        assert "err" in result

    def test_nonzero_exit_code(self):
        result = _format_result("out", "", 1)
        assert "[exit code: 1]" in result
        assert "out" in result

    def test_zero_exit_code_no_tag(self):
        result = _format_result("out", "", 0)
        assert "[exit code" not in result

    def test_no_output(self):
        result = _format_result("", "", 0)
        assert result == "[no output]"

    def test_exit_code_with_stderr(self):
        result = _format_result("", "fail", 42)
        assert "[exit code: 42]" in result
        assert "fail" in result


# ---------------------------------------------------------------------------
# _orchestra_truncate
# ---------------------------------------------------------------------------

class TestOrchestraTruncate:
    def test_under_limit(self):
        text = "short"
        result, truncated = _orchestra_truncate(text)
        assert result == "short"
        assert not truncated

    def test_at_limit(self):
        text = "x" * MAX_INLINE_OUTPUT
        result, truncated = _orchestra_truncate(text)
        assert result == text
        assert not truncated

    def test_over_limit(self):
        text = "x" * (MAX_INLINE_OUTPUT + 100)
        result, truncated = _orchestra_truncate(text)
        assert len(result) < len(text)
        assert truncated
        assert "[truncated]" in result

    def test_custom_limit(self):
        text = "hello world"
        result, truncated = _orchestra_truncate(text, max_len=5)
        assert truncated
        assert result.startswith("hello")
