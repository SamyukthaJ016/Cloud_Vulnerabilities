import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError

from backend.scripts.init_object_storage import ensure_bucket


def error(code):
    return ClientError({"Error": {"Code": code}}, "HeadBucket")


class ObjectStorageInitTest(unittest.TestCase):
    def test_existing_bucket_is_not_modified(self):
        client = Mock()
        ensure_bucket(client, "evidence")
        client.create_bucket.assert_not_called()

    def test_missing_bucket_is_created_and_verified(self):
        client = Mock()
        client.head_bucket.side_effect = [error("404"), None]
        ensure_bucket(client, "evidence")
        client.create_bucket.assert_called_once_with(Bucket="evidence")
        self.assertEqual(client.head_bucket.call_count, 2)

    def test_denied_bucket_access_is_not_hidden(self):
        client = Mock()
        client.head_bucket.side_effect = error("403")
        with self.assertRaises(ClientError):
            ensure_bucket(client, "evidence")
        client.create_bucket.assert_not_called()

    def test_concurrent_creation_is_verified(self):
        client = Mock()
        client.head_bucket.side_effect = [error("NoSuchBucket"), None]
        client.create_bucket.side_effect = error("BucketAlreadyOwnedByYou")
        ensure_bucket(client, "evidence")
        self.assertEqual(client.head_bucket.call_count, 2)


if __name__ == "__main__":
    unittest.main()
