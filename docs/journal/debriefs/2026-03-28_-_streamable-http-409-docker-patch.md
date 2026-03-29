# Streamable HTTP 409 Docker Patch

## Task Summary

Added a Docker-time patch for `mcp==1.26.0` so stale Streamable HTTP SSE sessions are replaced instead of returning `409 Conflict`, without modifying Maestro application code or changing the MCP SDK version.

## Files Changed

- `Dockerfile`: Installed `patch`, copied the new patch file after `pip install`, and applied it idempotently against `/usr/local/lib/python3.12/site-packages/mcp/server/streamable_http.py`.
- `patches/streamable_http_409.patch`: Added a unified diff that replaces the single-stream `409 Conflict` response with stale-stream cleanup and reconnection acceptance.

## Decisions And Surprises

- GNU `patch` rejected absolute-path application when reading the file header directly, so the Docker step patches the explicit target file path instead.
- The initial hand-written diff was malformed on a blank context line; regenerating the hunk shape against the `mcp==1.26.0` wheel fixed it.
- Verification used `docker build -t maestro-mcp-streamable-http-409-test .`, `docker run --rm --entrypoint sed ...`, and an entrypoint-overridden idempotence check inside the built image.
