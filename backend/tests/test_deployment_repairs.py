import unittest
from html.parser import HTMLParser
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
AUTH_ORIGIN = "https://auth.sc.deeptrustxai.com"


class PolicyParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy":
            self.policy = {
                values[0]: values[1:]
                for directive in attrs["content"].split(";")
                if (values := directive.split())
            }


class DeploymentRepairTests(unittest.TestCase):
    def test_both_grc_policies_allow_only_the_expected_sso_origin(self):
        parser = PolicyParser()
        parser.feed((ROOT / "grc-platform/frontend/index.html").read_text())
        nginx = (ROOT / "grc-platform/frontend/nginx.conf").read_text()
        for directive in ("connect-src", "frame-src"):
            self.assertIn(AUTH_ORIGIN, parser.policy[directive])
            self.assertNotIn("*", parser.policy[directive])
            self.assertIn(f"{directive} 'self' {AUTH_ORIGIN}", nginx)
        self.assertEqual(parser.policy["default-src"], ["'self'"])

    def test_minio_is_built_from_pinned_source_without_a_cached_image(self):
        compose = yaml.safe_load((ROOT / "deploy/dokploy/docker-compose.yml").read_text())
        minio = compose["services"]["minio"]
        self.assertEqual(minio["build"]["dockerfile"], "deploy/dokploy/minio.Dockerfile")
        self.assertNotIn("image", minio)
        self.assertNotIn("pull_policy", minio)
        dockerfile = (ROOT / minio["build"]["dockerfile"]).read_text()
        self.assertIn("test \"$(git rev-parse HEAD)\" = 9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a", dockerfile)
        self.assertIn("CGO_ENABLED=0", dockerfile)


if __name__ == "__main__":
    unittest.main()
