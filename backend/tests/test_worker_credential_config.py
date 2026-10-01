import unittest
from pathlib import Path

import yaml


class WorkerCredentialConfigTests(unittest.TestCase):
    def test_workers_receive_the_existing_credential_encryption_key(self):
        root = Path(__file__).resolve().parents[2]
        compose = yaml.safe_load(
            (root / "deploy/dokploy/docker-compose.yml").read_text()
        )
        for service in ("scan-worker", "sandbox-lab-worker", "scheduler-worker"):
            with self.subTest(service=service):
                self.assertEqual(
                    compose["services"][service]["environment"]["ENCRYPTION_KEY"],
                    "${ENCRYPTION_KEY:?ENCRYPTION_KEY is required}",
                )


if __name__ == "__main__":
    unittest.main()
