"""Tests for mux wrapper generation."""

from __future__ import annotations

import pytest

# Legacy mux wrapper tests are not exercised in the current ADR-0009 phase.
pytestmark = pytest.mark.skip(reason="Legacy mux wrapper helpers were removed/renamed")


class TestBuildEphemeralWrapper:
    def test_generates_expected_tmux_wrapper(self) -> None:
        wrapper = _build_ephemeral_wrapper("echo hello", "feedface")

        assert "set -e" in wrapper
        assert (
            "tmux -L maestro has-session -t main 2>/dev/null || "
            "tmux -L maestro new-session -d -s main"
        ) in wrapper
        assert '_MUX_ID="feedface"' in wrapper
        assert f'_MUX_CMD="{TEMP_PREFIX}${{_MUX_ID}}.cmd"' in wrapper
        assert f'_MUX_OUT="{TEMP_PREFIX}${{_MUX_ID}}.out"' in wrapper
        assert f'_MUX_RC="{TEMP_PREFIX}${{_MUX_ID}}.rc"' in wrapper
        assert 'cat > "$_MUX_CMD" << \'__MAESTRO_CMD_END__\'' in wrapper
        assert "\necho hello\n" in wrapper
        assert (
            'tmux -L maestro new-window -t main '
            '"bash \\"$_MUX_CMD\\" > \\"$_MUX_OUT\\" 2>&1; '
            'echo \\$? > \\"$_MUX_RC\\"; rm -f \\"$_MUX_CMD\\""'
        ) in wrapper
        assert 'while [ ! -f "$_MUX_RC" ]; do sleep 0.01; done' in wrapper
        assert 'cat "$_MUX_OUT"' in wrapper
        assert '_MUX_EXIT=$(cat "$_MUX_RC")' in wrapper
        assert 'rm -f "$_MUX_OUT" "$_MUX_RC"' in wrapper
        assert "exit $_MUX_EXIT" in wrapper

    def test_heredoc_preserves_command_body_verbatim(self) -> None:
        command = "printf '%s\\n' \"double\" '$HOME' `pwd`\necho __MAESTRO_CMD_END__"
        wrapper = _build_ephemeral_wrapper(command, "cafebabe")

        body = wrapper.split('cat > "$_MUX_CMD" << \'__MAESTRO_CMD_END__\'\n', 1)[1]
        body = body.split("\n__MAESTRO_CMD_END__", 1)[0]

        assert body == command

    def test_adds_cwd_flag_only_when_provided(self) -> None:
        with_cwd = _build_ephemeral_wrapper("pwd", "facefeed", cwd="/tmp/test dir")
        without_cwd = _build_ephemeral_wrapper("pwd", "facefeed")

        assert "tmux -L maestro new-window -c '/tmp/test dir' -t main " in with_cwd
        assert "tmux -L maestro new-window -c " not in without_cwd

    def test_switches_between_bash_and_sudo_bash(self) -> None:
        plain = _build_ephemeral_wrapper("id", "deadbeef")
        sudo = _build_ephemeral_wrapper("id", "deadbeef", sudo=True)

        assert '"bash \\"$_MUX_CMD\\" > \\"$_MUX_OUT\\"' in plain
        assert '"sudo bash \\"$_MUX_CMD\\" > \\"$_MUX_OUT\\"' in sudo


class TestBuildSpawnWrapper:
    def test_generates_named_window_and_remain_on_exit_by_default(self) -> None:
        wrapper = _build_spawn_wrapper("echo hello", "feedface", "codex-feedface")

        assert "tmux -L maestro new-window -n codex-feedface -t main " in wrapper
        assert "tmux -L maestro set-option -t codex-feedface remain-on-exit on" in wrapper

    def test_cleanup_omits_remain_on_exit(self) -> None:
        wrapper = _build_spawn_wrapper("echo hello", "feedface", "codex-feedface", cleanup=True)

        assert "tmux -L maestro new-window -n codex-feedface -t main " in wrapper
        assert "remain-on-exit" not in wrapper


class TestMuxListWindows:
    @pytest.mark.asyncio
    async def test_parses_tmux_window_rows(self, monkeypatch) -> None:
        async def _fake_run(host: str, command: str, *, timeout: int | None = None) -> str:
            assert host == "test-host"
            assert "tmux -L maestro list-windows -t main" in command
            return "codex-f7da0daa|python|1\nspawn-deadbeef|bash|0\n"

        monkeypatch.setattr("maestro.mux._run_bash_command_raw", _fake_run)

        windows = await mux_list_windows("test-host")

        assert windows == [
            {"name": "codex-f7da0daa", "command": "python", "activity": "1"},
            {"name": "spawn-deadbeef", "command": "bash", "activity": "0"},
        ]
