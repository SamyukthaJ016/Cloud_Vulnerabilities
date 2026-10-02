"""Exercise isolated route functions without booting scanner integrations."""

import ast
import logging
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import Mock

from fastapi import HTTPException


def route(name, **dependencies):
    source = ast.parse((Path(__file__).resolve().parents[1] / 'main.py').read_text())
    node = next(node for node in source.body if isinstance(node, ast.AsyncFunctionDef) and node.name == name)
    node.decorator_list = []
    namespace = {'Request': object, 'Optional': Optional, 'HTTPException': HTTPException,
                 'logger': logging.getLogger(__name__), **dependencies}
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<route>', 'exec'), namespace)
    return namespace[name]


class DashboardScopeTests(unittest.IsolatedAsyncioTestCase):
    async def test_inline_iac_demo_resolves_proof_scan_id(self):
        get = route('get_sandbox_lab', get_user_id=lambda _: 'user-a',
                    _request_tenant_id=lambda *args: 'tenant-a',
                    get_sandbox_lab_run=lambda *args, **kwargs: {'scan_job_id': None, 'proof_payload': {'proof': {'scan_id': 17}}},
                    list_sandbox_lab_events=lambda _: [])
        self.assertEqual((await get('lab-iac', object()))['lab']['scan_ids'], [17])

    async def test_lab_resolves_only_owned_job(self):
        lab_lookup = Mock(return_value={'scan_job_id': 'job-k8s'})
        job_lookup = Mock(return_value={'scan_ids': [22]})
        get = route('get_sandbox_lab', get_user_id=lambda _: 'user-a',
                    _request_tenant_id=lambda *args: 'tenant-a', get_sandbox_lab_run=lab_lookup,
                    get_scan_job=job_lookup, list_sandbox_lab_events=lambda _: [])
        result = await get('lab-k8s', object())
        self.assertEqual(result['lab']['scan_ids'], [22])
        lab_lookup.assert_called_once_with('lab-k8s', user_id='user-a', tenant_id='tenant-a')
        job_lookup.assert_called_once_with('job-k8s', user_id='user-a', tenant_id='tenant-a')

    async def test_other_tenant_lab_is_denied_before_job_lookup(self):
        job_lookup = Mock()
        get = route('get_sandbox_lab', get_user_id=lambda _: 'user-b',
                    _request_tenant_id=lambda *args: 'tenant-b', get_sandbox_lab_run=lambda *args, **kwargs: None,
                    get_scan_job=job_lookup)
        with self.assertRaises(HTTPException) as error:
            await get('lab-k8s', object())
        self.assertEqual(error.exception.status_code, 404)
        job_lookup.assert_not_called()

    async def test_findings_count_and_page_share_user_tenant_and_scan_scope(self):
        cursor = Mock()
        cursor.__enter__ = Mock(return_value=cursor)
        cursor.__exit__ = Mock(return_value=False)
        cursor.fetchone.return_value = (247,)
        cursor.fetchall.return_value = [('pod', 'kubernetes', 'HIGH', 'privileged', 'kubernetes', None)] * 47
        connection = Mock()
        connection.cursor.return_value = cursor
        get = route('get_latest_findings', get_user_id=lambda _: 'user-a',
                    _request_tenant_id=lambda *args, **kwargs: 'tenant-a', get_conn=lambda: connection)
        result = await get(object(), limit=200, offset=200, scan_ids='22')
        self.assertEqual(result['total'], 247)
        self.assertFalse(result['has_more'])
        count_call, page_call = cursor.execute.call_args_list
        self.assertEqual(count_call.args[1], ('user-a', 'tenant-a', [22]))
        self.assertEqual(page_call.args[1], ('user-a', 'tenant-a', [22], 200, 200))
        self.assertIn('f.id DESC LIMIT %s OFFSET %s', page_call.args[0])

    async def test_invalid_scan_selection_is_not_an_unfiltered_query(self):
        cursor = Mock()
        cursor.__enter__ = Mock(return_value=cursor)
        cursor.__exit__ = Mock(return_value=False)
        connection = Mock()
        connection.cursor.return_value = cursor
        get = route('get_latest_findings', get_user_id=lambda _: 'user-a',
                    _request_tenant_id=lambda *args, **kwargs: 'tenant-a', get_conn=lambda: connection)
        result = await get(object(), scan_ids='not-a-scan')
        self.assertEqual(result['status'], 'error')
        cursor.execute.assert_not_called()

    async def test_history_uses_the_selected_run(self):
        cursor = Mock()
        cursor.__enter__ = Mock(return_value=cursor)
        cursor.__exit__ = Mock(return_value=False)
        cursor.fetchall.return_value = []
        connection = Mock()
        connection.cursor.return_value = cursor
        get = route('get_scan_history', get_user_id=lambda _: 'user-a',
                    _request_tenant_id=lambda *args, **kwargs: 'tenant-a', get_conn=lambda: connection)
        result = await get(object(), scan_ids='22')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(cursor.execute.call_args.args[1], ('user-a', 'tenant-a', '30 days', [22], [22]))


if __name__ == '__main__':
    unittest.main()
