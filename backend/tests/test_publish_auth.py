"""Verify the current authentication boundary during the legacy-path merge."""
import ast
from pathlib import Path
import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.mcp_runtime import isolated_mcp_runtime
from backend.tenant_security import request_identity


class PublishAuthenticationTest(unittest.IsolatedAsyncioTestCase):
    async def test_all_application_prefixes_reject_legacy_cookie_identity(self):
        source = Path(__file__).parents[1] / "main.py"
        tree = ast.parse(source.read_text())
        middleware = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                          and node.name == "CloudGuardIdentityMiddleware")
        namespace = dict(BaseHTTPMiddleware=BaseHTTPMiddleware, Request=Request,
                         HTTPException=HTTPException, JSONResponse=JSONResponse,
                         cloudguard_auth_required=lambda: True,
                         request_identity=request_identity,
                         isolated_mcp_runtime=isolated_mcp_runtime)
        exec(compile(ast.Module(body=[middleware], type_ignores=[]), str(source), "exec"), namespace)
        app = FastAPI()
        app.add_middleware(namespace["CloudGuardIdentityMiddleware"])
        paths = ["/api/billing/subscription", "/api/grc/sync", "/api/credentials/providers/status",
                 "/api/scan-jobs", "/scan/multi-cloud", "/posture/dashboard",
                 "/report/1", "/providers", "/agent/chat"]
        for path in paths:
            app.add_api_route(path, lambda: {"reached": True}, methods=["GET"])
        with patch.dict("os.environ", {"CLOUDGUARD_AUTH_REQUIRED": "true"}):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://test") as client:
                for path in paths:
                    response = await client.get(path, headers={
                        "Cookie": "cloudguard_user_id=foreign-user; session_id=forged",
                        "X-User-ID": "foreign-user", "X-Tenant-ID": "foreign-tenant"})
                    self.assertEqual(response.status_code, 401, (path, response.text))


if __name__ == "__main__":
    unittest.main()
