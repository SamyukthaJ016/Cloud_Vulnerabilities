"""AWS demo provisioning contracts; no real AWS calls are made."""

import ast
import copy
import json
import logging
import os
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from backend.aws_sandbox import allowed_aws_sandbox_accounts, verify_aws_sandbox_identity
from backend.mcp_servers.aws_server import AWSMCPServer


def load_functions(**dependencies):
    source = ast.parse((Path(__file__).resolve().parents[1] / 'main.py').read_text())
    names = {'_aws_session_for_lab', '_deploy_aws_sandbox_lab', '_destroy_aws_sandbox_resources', '_sandbox_provider_readiness', '_cleanup_resource_absent'}
    nodes = [node for node in source.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    namespace = {'Dict': Dict, 'List': List, 'Any': Any, 'Optional': Optional, 'uuid': uuid,
                 'os': os, 'json': json, 'logger': logging.getLogger(__name__),
                 'allowed_aws_sandbox_accounts': allowed_aws_sandbox_accounts,
                 'verify_aws_sandbox_identity': verify_aws_sandbox_identity, **dependencies}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<aws-demo>', 'exec'), namespace)
    return namespace


class AwsSandboxTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {'SANDBOX_AWS_ACCOUNT_IDS': '123456789012'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.clients = {name: Mock() for name in ('sts', 's3', 'iam', 'ec2')}
        self.clients['sts'].get_caller_identity.return_value = {'Account': '123456789012', 'Arn': 'arn:aws:iam::123456789012:user/CloudGuardSandboxWorker'}
        self.clients['ec2'].create_vpc.return_value = {'Vpc': {'VpcId': 'vpc-lab'}}
        self.clients['ec2'].create_security_group.return_value = {'GroupId': 'sg-lab'}
        self.clients['iam'].list_user_policies.return_value = {'PolicyNames': ['CloudGuardSandboxWildcard']}
        self.clients['iam'].list_access_keys.return_value = {'AccessKeyMetadata': []}
        self.session = Mock()
        self.session.client.side_effect = lambda service: self.clients[service]
        self.snapshots = []
        self.functions = load_functions(update_sandbox_lab=lambda lab_id, **fields: self.snapshots.append(copy.deepcopy(fields)))
        self.functions['_aws_session_for_lab'] = lambda *args, **kwargs: (self.session, 'ap-south-1')
        self.lab = {'lab_id': 'lab-test', 'resource_prefix': 'cg-123456abcdef', 'expires_at': '2026-10-03T12:00:00Z'}

    async def test_demo_creates_four_tracked_inert_resources(self):
        result = await self.functions['_deploy_aws_sandbox_lab'](self.lab)
        self.assertEqual([r['type'] for r in result['resources']], ['s3_bucket', 'vpc', 'security_group', 'iam_user'])
        self.assertEqual([len(snapshot['resources']) for snapshot in self.snapshots], [1, 2, 3, 4])
        self.assertTrue(all(r['account_id'] == '123456789012' for r in result['resources']))
        self.clients['s3'].put_object.assert_not_called()
        self.clients['iam'].create_access_key.assert_not_called()
        self.clients['iam'].create_login_profile.assert_not_called()
        self.clients['ec2'].run_instances.assert_not_called()
        self.clients['ec2'].create_internet_gateway.assert_not_called()
        rules = self.clients['ec2'].authorize_security_group_ingress.call_args.kwargs['IpPermissions']
        self.assertEqual({r.get('FromPort') for r in rules if r['IpProtocol'] == 'tcp'}, {22, 3389, 5432})
        tags = self.clients['s3'].put_bucket_tagging.call_args.kwargs['Tagging']['TagSet']
        self.assertIn({'Key': 'cloudguard-lab-id', 'Value': 'lab-test'}, tags)

    async def test_wrong_account_refuses_all_resource_creation(self):
        self.clients['sts'].get_caller_identity.return_value['Account'] = '999999999999'
        with self.assertRaisesRegex(RuntimeError, 'not in SANDBOX'):
            await self.functions['_deploy_aws_sandbox_lab'](self.lab)
        self.clients['s3'].create_bucket.assert_not_called()
        self.clients['iam'].create_user.assert_not_called()
        self.clients['ec2'].create_vpc.assert_not_called()

    def test_missing_allowlist_and_root_credentials_are_rejected(self):
        with patch.dict(os.environ, {'SANDBOX_AWS_ACCOUNT_IDS': ''}):
            with self.assertRaisesRegex(RuntimeError, 'approved isolated'):
                verify_aws_sandbox_identity(self.clients['sts'])
        self.clients['sts'].get_caller_identity.return_value['Arn'] = 'arn:aws:iam::123456789012:root'
        with self.assertRaisesRegex(RuntimeError, 'not root'):
            verify_aws_sandbox_identity(self.clients['sts'])

    def test_malformed_allowlist_fails_closed(self):
        with patch.dict(os.environ, {'SANDBOX_AWS_ACCOUNT_IDS': '123456789012,not-an-account'}):
            with self.assertRaisesRegex(RuntimeError, '12-digit'):
                allowed_aws_sandbox_accounts()

    def test_catalog_blocks_missing_account_configuration(self):
        functions = load_functions(_sandbox_provider_deploy_enabled=lambda _: True,
                                   _sandbox_credential_ready=lambda *args: {'ready': True, 'reason': 'Ready', 'source': 'stored'})
        with patch.dict(os.environ, {'SANDBOX_AWS_ACCOUNT_IDS': ''}):
            readiness = functions['_sandbox_provider_readiness']('aws', 'user-a')
        self.assertFalse(readiness['enabled'])
        self.assertIn('SANDBOX_AWS_ACCOUNT_IDS', readiness['reason'])

    async def test_account_public_access_block_is_not_bypassed(self):
        self.clients['s3'].put_bucket_policy.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'PutBucketPolicy')
        result = await self.functions['_deploy_aws_sandbox_lab'](self.lab)
        self.assertFalse(result['proof_payload']['public_bucket_policy_applied'])
        self.assertNotIn('s3control', [call.args[0] for call in self.session.client.call_args_list])

    async def test_partial_failure_keeps_resource_manifest_and_runs_cleanup(self):
        self.clients['iam'].put_user_policy.side_effect = RuntimeError('Policy denied')
        with self.assertRaisesRegex(RuntimeError, 'Policy denied'):
            await self.functions['_deploy_aws_sandbox_lab'](self.lab)
        self.assertEqual(len(self.snapshots[-1]['resources']), 4)
        self.clients['s3'].delete_bucket.assert_called_once()
        self.clients['iam'].delete_user.assert_called_once()
        self.clients['ec2'].delete_security_group.assert_called_once()
        self.clients['ec2'].delete_vpc.assert_called_once()

    def test_cleanup_refuses_a_different_account(self):
        self.clients['sts'].get_caller_identity.return_value['Account'] = '999999999999'
        resources = [{'type': 'vpc', 'name': 'vpc-lab', 'account_id': '123456789012'}]
        with self.assertRaisesRegex(RuntimeError, 'cleanup refused'):
            self.functions['_destroy_aws_sandbox_resources'](self.lab, resources)
        self.clients['ec2'].delete_vpc.assert_not_called()

    def test_cleanup_works_after_deployment_allowlist_is_removed(self):
        resources = [{'type': 'vpc', 'name': 'vpc-lab', 'account_id': '123456789012'}]
        with patch.dict(os.environ, {'SANDBOX_AWS_ACCOUNT_IDS': ''}):
            result = self.functions['_destroy_aws_sandbox_resources'](self.lab, resources)
        self.assertEqual(result['errors'], [])
        self.clients['ec2'].delete_vpc.assert_called_once()

    def test_already_deleted_resources_are_successful_cleanup(self):
        cases = [('s3_bucket', 's3', 'delete_bucket', 'NoSuchBucket'),
                 ('iam_user', 'iam', 'list_user_policies', 'NoSuchEntity'),
                 ('security_group', 'ec2', 'delete_security_group', 'InvalidGroup.NotFound'),
                 ('vpc', 'ec2', 'delete_vpc', 'InvalidVpcID.NotFound')]
        resources = []
        for kind, service, operation, code in cases:
            getattr(self.clients[service], operation).side_effect = ClientError({'Error': {'Code': code}}, operation)
            resources.append({'type': kind, 'name': kind, 'account_id': '123456789012'})
        result = self.functions['_destroy_aws_sandbox_resources'](self.lab, resources)
        self.assertEqual(result['errors'], [])
        self.assertEqual(len(result['deleted']), 4)
        self.assertTrue(all(r['already_absent'] for r in result['deleted']))

    def test_cleanup_never_swallows_permission_failures(self):
        self.clients['ec2'].delete_vpc.side_effect = ClientError({'Error': {'Code': 'UnauthorizedOperation'}}, 'DeleteVpc')
        result = self.functions['_destroy_aws_sandbox_resources'](self.lab, [{'type': 'vpc', 'name': 'vpc-lab', 'account_id': '123456789012'}])
        self.assertEqual(len(result['errors']), 1)

    def test_saved_role_is_used_for_provisioning_too(self):
        credential = SimpleNamespace(aws_region='ap-south-1', aws_access_key_id='test-key', aws_secret_access_key='test-secret',
                                     aws_session_token=None, aws_role_arn='arn:aws:iam::123456789012:role/CloudGuardSandboxWorker')
        get_session = Mock(return_value=self.session)
        functions = load_functions(_require_provider_enabled=lambda _: None, _credential_for_lab=lambda _: credential, get_aws_session=get_session)
        functions['_aws_session_for_lab'](self.lab)
        self.assertEqual(get_session.call_args.args[1]['role_arn'], credential.aws_role_arn)

    def test_demo_cannot_create_resources_outside_scanner_region(self):
        get_session = Mock()
        functions = load_functions(_require_provider_enabled=lambda _: None,
                                   _credential_for_lab=lambda _: SimpleNamespace(aws_region='ap-south-1'),
                                   get_aws_session=get_session)
        with self.assertRaisesRegex(RuntimeError, 'match the saved'):
            functions['_aws_session_for_lab']({**self.lab, 'region': 'us-east-1'})
        get_session.assert_not_called()

    async def test_scanner_detects_public_policy_without_public_acl(self):
        server = AWSMCPServer.__new__(AWSMCPServer)
        server.s3 = Mock()
        server.s3.get_bucket_acl.return_value = {'Grants': []}
        server.s3.get_bucket_policy_status.return_value = {'PolicyStatus': {'IsPublic': True}}
        server.s3.get_bucket_versioning.return_value = {}
        server.s3.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {}}
        result = await server._check_s3_security('cg-test')
        issues = {f['issue'] for f in result['findings']}
        self.assertIn('Public S3 Bucket Policy', issues)
        self.assertIn('S3 Block Public Access Disabled', issues)
        self.assertNotIn('Public S3 Bucket', issues)
        self.assertNotIn('S3 Encryption Disabled', issues)

    async def test_policy_read_denial_does_not_invent_public_access(self):
        server = AWSMCPServer.__new__(AWSMCPServer)
        server.s3 = Mock()
        server.s3.get_bucket_acl.return_value = {'Grants': []}
        server.s3.get_bucket_policy_status.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'GetBucketPolicyStatus')
        server.s3.get_bucket_encryption.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'GetBucketEncryption')
        server.s3.get_bucket_versioning.return_value = {'Status': 'Enabled'}
        server.s3.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}}
        result = await server._check_s3_security('cg-test')
        self.assertEqual(result['findings'], [])

    async def test_generated_iam_and_security_group_rules_are_detected(self):
        server = AWSMCPServer.__new__(AWSMCPServer)
        server.iam = Mock()
        server.iam.list_mfa_devices.return_value = {'MFADevices': []}
        server.iam.list_user_policies.return_value = {'PolicyNames': ['CloudGuardSandboxWildcard']}
        server.iam.get_user_policy.return_value = {'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}
        server.iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
        result = await server._check_iam_security('cg-test-no-mfa')
        self.assertIn('IAM User Without MFA', {f['issue'] for f in result['findings']})
        self.assertIn('IAM User Has Wildcard Administrative Policy', {f['issue'] for f in result['findings']})
        lab = await self.functions['_deploy_aws_sandbox_lab'](self.lab)
        rules = self.clients['ec2'].authorize_security_group_ingress.call_args.kwargs['IpPermissions']
        findings = server._check_security_group_security({'group_id': lab['resources'][2]['name'], 'ip_permissions': rules})
        self.assertEqual({f['severity'] for f in findings}, {'HIGH', 'CRITICAL'})

    def test_compose_passes_account_guard_to_api_and_workers(self):
        import yaml
        root = Path(__file__).resolve().parents[2]
        for file, services in [('deploy/dokploy/docker-compose.yml', ['backend', 'sandbox-lab-worker']),
                               ('deploy/e2e/portal-compose.yml', ['backend']),
                               ('deploy/e2e/worker-compose.yml', ['sandbox-lab-worker'])]:
            compose = yaml.safe_load((root / file).read_text())
            for service in services:
                self.assertEqual(compose['services'][service]['environment']['SANDBOX_AWS_ACCOUNT_IDS'], '${SANDBOX_AWS_ACCOUNT_IDS:-}')

    def test_write_policy_never_grants_compute_or_lab_login_credentials(self):
        import fnmatch
        policy = json.loads((Path(__file__).resolve().parents[2] / 'deploy/aws-lab/worker-policy.template.json').read_text())
        allowed = {action for statement in policy['Statement'] if statement['Effect'] == 'Allow'
                   for action in ([statement['Action']] if isinstance(statement['Action'], str) else statement['Action'])}
        self.assertNotIn('ec2:RunInstances', allowed)
        self.assertNotIn('iam:CreateAccessKey', allowed)
        self.assertNotIn('iam:CreateLoginProfile', allowed)
        for statement in policy['Statement']:
            actions = statement['Action'] if isinstance(statement['Action'], list) else [statement['Action']]
            if statement['Effect'] == 'Allow' and 'iam:PutUserPolicy' in actions:
                self.assertFalse(fnmatch.fnmatch('arn:aws:iam::SANDBOX_ACCOUNT_ID:user/CloudGuardSandboxWorker', statement['Resource']))


if __name__ == '__main__':
    unittest.main()
