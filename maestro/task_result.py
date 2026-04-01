from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import maestro.relay as relay
from maestro.relay import _auth_error, _transfer_auth_ok


async def task_result(request: Request) -> Response:
    """Return task result via HTTP, enabling bash_tool wait loops."""
    if not _transfer_auth_ok(request):
        return _auth_error()

    if relay._TASK_LOOKUP is None:
        return JSONResponse(
            {"error": "not_configured", "detail": "task lookup not available"},
            status_code=503,
        )

    task_id = request.path_params.get("task_id", "")
    if not task_id:
        return JSONResponse(
            {"error": "bad_request", "detail": "task_id path parameter required"},
            status_code=400,
        )

    result = await relay._TASK_LOOKUP(task_id)
    if result is None:
        return JSONResponse(
            {"error": "not_found", "detail": f"task '{task_id}' not found or evicted"},
            status_code=404,
        )

    status = result.get("status", "unknown")
    if status == "running":
        return JSONResponse(result, status_code=202)

    relay._audit("task_result_retrieved", task_id=task_id, status=status)
    return JSONResponse(result, status_code=200)
