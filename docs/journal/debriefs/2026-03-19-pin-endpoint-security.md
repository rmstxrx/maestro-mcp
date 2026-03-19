# 2026-03-19 — PIN Endpoint Security Guard

## Task
Add a secure-channel guard to `/admin/rotate-pin` and `/approve` routes in `server.py`, blocking plaintext PIN exposure over LAN HTTP.

## Files Changed
- **server.py**: Added CF-Ray / localhost check to both `/admin/rotate-pin` (blocks GET+POST) and `/approve` (blocks POST only). Returns 403 with explanation when request arrives over an insecure channel.

## Decisions
- `/approve` GET is left open so users can still view the consent page over LAN — only POST (which carries the PIN) is blocked.
- `/admin/rotate-pin` blocks both methods since even viewing the rotation form on an insecure channel could mislead users into submitting.
- "localhost" string is included alongside `127.0.0.1` / `::1` for defense-in-depth, though Starlette typically resolves to IP.

## Surprises
None — straightforward guard, all 54 existing tests pass unchanged.
