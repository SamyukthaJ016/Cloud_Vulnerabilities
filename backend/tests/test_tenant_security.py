"""Regression tests for CloudGuard tenant-bound machine credentials."""

import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from backend.tenant_security import require_connector_identity


TEST_CONNECTOR_CREDENTIALS = """{
  "tenant-a-evidence": {
    "token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "tenant_id": "tenant-a",
    "user_id": "user-a",
    "scopes": ["evidence:write", "worker:heartbeat"]
  },
  "tenant-b-grc": {
    "token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "tenant_id": "tenant-b",
    "user_id": "user-b",
    "scopes": ["grc:read"]
  }
}"""


def connector_request(connector_id: str, token: str, extra_headers: dict[str, str] | None = None) -> Request:
    headers = {
        "x-connector-id": connector_id,
        "authorization": f"Bearer {token}",
    }
    headers.update(extra_headers or {})
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "path": "/api/evidence",
            "headers": [(name.encode(), value.encode()) for name, value in headers.items()],
        }
    )


class TenantConnectorSecurityTests(unittest.TestCase):
    @patch.dict(os.environ, {"CONNECTOR_CREDENTIALS_JSON": TEST_CONNECTOR_CREDENTIALS}, clear=False)
    def test_connector_identity_comes_from_the_secret_not_request_headers(self):
        request = connector_request(
            "tenant-a-evidence",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            {"x-cloudguard-user": "user-b", "x-cloudguard-tenant": "tenant-b"},
        )

        identity = require_connector_identity(request, "evidence:write")

        self.assertEqual(identity.tenant_id, "tenant-a")
        self.assertEqual(identity.user_id, "user-a")

    @patch.dict(os.environ, {"CONNECTOR_CREDENTIALS_JSON": TEST_CONNECTOR_CREDENTIALS}, clear=False)
    def test_token_from_one_tenant_cannot_authenticate_another_tenant_connector(self):
        request = connector_request("tenant-b-grc", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        with self.assertRaises(HTTPException) as error:
            require_connector_identity(request, "grc:read")

        self.assertEqual(error.exception.status_code, 401)

    @patch.dict(os.environ, {"CONNECTOR_CREDENTIALS_JSON": TEST_CONNECTOR_CREDENTIALS}, clear=False)
    def test_connector_scope_is_enforced(self):
        request = connector_request("tenant-a-evidence", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        with self.assertRaises(HTTPException) as error:
            require_connector_identity(request, "grc:read")

        self.assertEqual(error.exception.status_code, 403)
