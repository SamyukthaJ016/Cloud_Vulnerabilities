"""Navigation HTML shells must load before browser-authenticated API requests."""

import ast
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse, JSONResponse


def test_navigation_shells_load_while_scan_and_schedule_data_remain_protected():
    source = ast.parse((Path(__file__).resolve().parents[1] / 'main.py').read_text())
    middleware = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == 'CloudGuardIdentityMiddleware')

    def require_identity(_request):
        raise HTTPException(status_code=401, detail='Bearer token required')

    @asynccontextmanager
    async def isolated_runtime():
        yield

    namespace = dict(BaseHTTPMiddleware=BaseHTTPMiddleware, Request=Request,
                     HTTPException=HTTPException, JSONResponse=JSONResponse,
                     cloudguard_auth_required=lambda: True, request_identity=require_identity,
                     isolated_mcp_runtime=isolated_runtime)
    exec(compile(ast.Module(body=[middleware], type_ignores=[]), '<middleware>', 'exec'), namespace)
    app = FastAPI()
    app.add_middleware(namespace['CloudGuardIdentityMiddleware'])

    async def page():
        return HTMLResponse('<html>CloudGuard</html>')

    paths = ['/history', '/scheduled_scans', '/schedules']
    for path in paths:
        app.get(path)(page)

    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            for path in paths:
                response = await client.get(path)
                assert response.status_code == 200, path
                assert 'text/html' in response.headers['content-type']
            for path in ['/api/scans', '/api/latest-findings', '/api/dashboard-scope', '/posture/dashboard', '/api/schedules', '/api/schedules/1']:
                assert (await client.get(path)).status_code == 401, path
            for method, path in [('POST', '/scan/schedule'), ('POST', '/api/schedules/1/run'), ('PUT', '/api/schedules/1'), ('DELETE', '/api/schedules/1')]:
                assert (await client.request(method, path)).status_code == 401, path

    asyncio.run(check())
