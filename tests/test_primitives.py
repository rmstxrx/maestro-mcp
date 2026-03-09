"""Tests for pure functions across maestro modules."""
import json
import sys
from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP

# Add project root to path so we can import modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from maestro.hosts import (
    HostConfig,
    HostShell,
    HostStatus,
    HOSTS,
    _format_result,
    _ps_quote,
    _resolve_host,
    _wrap_command,
    init_hosts,
)
from maestro.transport import _is_transient_failure
from maestro.tools.fleet import register_tools
from maestro.tools.orchestra import (
    TASK_REGISTRY,
    _REGISTRY_LOCK,
    _auto_promote,
    _orchestra_truncate,
    configure_orchestra,
)
from maestro.config import MaestroConfig

_config = MaestroConfig.from_env()
MAX_INLINE_OUTPUT = _config.max_inline_output

# Initialize hosts (noop if hosts.yaml missing) and configure orchestra for truncate tests
try:
    init_hosts()
except FileNotFoundError:
    pass

# Minimal configure so _orchestra_truncate works without full wiring
configure_orchestra(
    config=_config,
    resolve_host=_resolve_host,
    wrap_command=_wrap_command,
    format_result=_format_result,
    update_host_status=lambda *a, **kw: None,  # type: ignore[arg-type]
    host_status=HostStatus,
    ensure_connection=lambda *a, **kw: None,  # type: ignore[arg-type]
    teardown_connection=lambda *a, **kw: None,  # type: ignore[arg-type]
    async_run=lambda *a, **kw: None,  # type: ignore[arg-type]
    is_transient_failure=_is_transient_failure,
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
    @pytest.mark.skipif(not HOSTS, reason="hosts.yaml not present")
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


# ---------------------------------------------------------------------------
# MaestroConfig
# ---------------------------------------------------------------------------

class TestMaestroConfig:
    def test_orchestra_output_dir_is_env_overridable(self, monkeypatch, tmp_path):
        monkeypatch.setenv("MAESTRO_ORCHESTRA_OUTPUT_DIR", str(tmp_path))
        config = MaestroConfig.from_env()
        assert config.orchestra_output_dir == tmp_path

    def test_trusted_client_ids_are_loaded_from_env(self, monkeypatch):
        monkeypatch.setenv("MAESTRO_TRUSTED_CLIENT_IDS", " alpha, beta ,, gamma ")
        config = MaestroConfig.from_env()
        assert config.trusted_client_ids == frozenset({"alpha", "beta", "gamma"})


# ---------------------------------------------------------------------------
# Fleet tools
# ---------------------------------------------------------------------------

class TestGeminiSessions:
    @pytest.mark.asyncio
    async def test_wraps_success_output(self, monkeypatch):
        monkeypatch.setattr("maestro.tools.fleet._resolve_host", lambda host: object())

        async def _fake_run(host, command, timeout):
            assert host == "test-host"
            assert command == "gemini --list-sessions"
            assert timeout == 15
            return 0, "session-1\nsession-2"

        monkeypatch.setattr("maestro.tools.fleet._orchestra_run_cli", _fake_run)

        mcp = FastMCP("test")
        register_tools(mcp, _config)
        _, call_result = await mcp.call_tool("gemini_sessions", {"host": "test-host"})

        result = json.loads(call_result["result"])
        assert result == {
            "host": "test-host",
            "sessions": "session-1\nsession-2",
        }

    @pytest.mark.asyncio
    async def test_wraps_error_output(self, monkeypatch):
        monkeypatch.setattr("maestro.tools.fleet._resolve_host", lambda host: object())

        async def _fake_run(host, command, timeout):
            assert host == "test-host"
            assert command == "gemini --list-sessions"
            assert timeout == 15
            return 1, "gemini not installed"

        monkeypatch.setattr("maestro.tools.fleet._orchestra_run_cli", _fake_run)

        mcp = FastMCP("test")
        register_tools(mcp, _config)
        _, call_result = await mcp.call_tool("gemini_sessions", {"host": "test-host"})

        result = json.loads(call_result["result"])
        assert result == {
            "host": "test-host",
            "error": "gemini not installed",
        }


# ---------------------------------------------------------------------------
# _auto_promote
# ---------------------------------------------------------------------------

class TestAutoPromote:
    @pytest.mark.asyncio
    async def test_output_file_factory_uses_random_task_id(self, monkeypatch, tmp_path):
        task_id = "feedfacecafebeef"
        output_holder: list[Path | None] = [None]
        expected_output = tmp_path / f"codex_{task_id}.txt"

        async def _execute() -> str:
            output_file = output_holder[0]
            assert output_file == expected_output
            return json.dumps({"output_file": str(output_file)})

        monkeypatch.setattr("maestro.tools.orchestra.secrets.token_hex", lambda _: task_id)

        result = await _auto_promote(
            _execute,
            block_timeout=0,
            agent="codex",
            host="test-host",
            prompt="repeatable prompt",
            output_file_factory=lambda tid: tmp_path / f"codex_{tid}.txt",
            output_holder=output_holder,
        )

        payload = json.loads(result)
        assert payload["task_id"] == task_id
        assert output_holder[0] == expected_output

        async with _REGISTRY_LOCK:
            ts = TASK_REGISTRY[task_id]
        await ts._done_event.wait()

        assert ts.output_file == expected_output
        assert json.loads(ts.result_json)["output_file"] == str(expected_output)

        async with _REGISTRY_LOCK:
            TASK_REGISTRY.pop(task_id, None)
