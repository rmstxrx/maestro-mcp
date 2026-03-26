"""Tests for mux wrapper generation."""

from __future__ import annotations

from maestro.mux import TEMP_PREFIX, _build_ephemeral_wrapper


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
