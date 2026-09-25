import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store, now


class VerificationFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        template = self.service.create_template(
            "issuer-a", "issuer", "student", "学生身份",
            [{"name": "name", "required": True}, {"name": "program", "required": True}, {"name": "degree", "required": False}],
            365,
        )
        self.credential = self.service.issue(
            "issuer-a", "issuer", template["id"], "alice",
            {"name": "Alice", "program": "CS", "degree": "BSc"}, "issue-1",
        )
        self.verification = self.service.verification

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def _request(self, fields=("name", "program"), ttl=30):
        return self.verification.create_request(
            "bank-1", "verifier", self.credential["id"], "开户实名核验", list(fields), ttl
        )

    def _consent(self, request_id):
        return self.verification.consent("alice", "holder", request_id)

    def test_full_one_time_flow_and_record_kept(self):
        request = self._request()
        self.assertEqual("pending", request["status"])
        self.assertEqual("bank-1", request["verifier"])
        consent = self._consent(request["id"])
        self.assertEqual({"name", "program"}, set(consent["approved_fields"]))
        token = consent["one_time_token"]

        result = self.verification.redeem("bank-1", "verifier", token)
        self.assertTrue(result["valid"])
        self.assertEqual({"name": "Alice", "program": "CS"}, result["claims"])
        self.assertEqual("active", result["credential_status"])

        # 第一次成功核验后原凭证立即失效
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem("bank-1", "verifier", token)
        self.assertEqual(409, ctx.exception.status)

        # 持有人事后可查看核验记录（谁、用途、看了哪些字段）
        records = self.verification.list_records("alice", "holder")
        self.assertEqual(1, len(records))
        record = records[0]
        self.assertEqual("bank-1", record["verifier"])
        self.assertEqual("开户实名核验", record["purpose"])
        self.assertEqual({"name", "program"}, set(record["disclosed_fields"]))
        self.assertNotIn("degree", record["disclosed_claims"])

        # 已完成核验的申请不能再撤回，但记录保留
        with self.assertRaises(ApiError) as ctx:
            self.verification.withdraw("alice", "holder", request["id"])
        self.assertEqual(409, ctx.exception.status)
        self.assertEqual(1, len(self.verification.list_records("alice", "holder")))

    def test_fields_outside_consent_rejected_and_token_still_usable(self):
        token = self._consent(self._request()["id"])["one_time_token"]
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem("bank-1", "verifier", token, ["name", "degree"])
        self.assertEqual(403, ctx.exception.status)
        # 越界被拒不消耗凭证，按同意范围仍可核验成功
        result = self.verification.redeem("bank-1", "verifier", token, ["name"])
        self.assertEqual({"name": "Alice"}, result["claims"])

    def test_expired_request_and_token_rejected(self):
        # 过期后不能再同意
        stale = self._request(ttl=1)
        self.verification.clock = lambda: now() + timedelta(minutes=2)
        with self.assertRaises(ApiError) as ctx:
            self._consent(stale["id"])
        self.assertEqual(410, ctx.exception.status)

        # 已同意的凭证过期后拒绝兑付
        self.verification.clock = now
        token = self._consent(self._request(ttl=1)["id"])["one_time_token"]
        self.verification.clock = lambda: now() + timedelta(minutes=2)
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem("bank-1", "verifier", token)
        self.assertEqual(410, ctx.exception.status)

    def test_withdraw_invalidates_unused_request_but_keeps_records(self):
        # 未同意就撤回：申请失效，不能再同意
        first = self._request()
        self.verification.withdraw("alice", "holder", first["id"])
        with self.assertRaises(ApiError) as ctx:
            self._consent(first["id"])
        self.assertEqual(409, ctx.exception.status)

        # 同意之后撤回：未使用的凭证作废，兑付被拒
        second = self._request()
        token = self._consent(second["id"])["one_time_token"]
        self.verification.withdraw("alice", "holder", second["id"])
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem("bank-1", "verifier", token)
        self.assertEqual(409, ctx.exception.status)

        # 另一笔已完成的核验记录不受撤回影响，继续保留
        done = self._request()
        done_token = self._consent(done["id"])["one_time_token"]
        self.verification.redeem("bank-1", "verifier", done_token)
        self.verification.withdraw("alice", "holder", self._request()["id"])
        records = self.verification.list_records("alice", "holder")
        self.assertEqual(1, len(records))
        self.assertEqual(done["id"], records[0]["request_id"])

    def test_concurrent_redeem_only_one_succeeds(self):
        token = self._consent(self._request()["id"])["one_time_token"]
        barrier = threading.Barrier(8)
        outcomes = []

        def attempt():
            barrier.wait(timeout=5)
            try:
                self.verification.redeem("bank-1", "verifier", token)
                outcomes.append("ok")
            except ApiError as exc:
                outcomes.append(exc.status)

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, outcomes.count("ok"))
        self.assertEqual(7, outcomes.count(409))
        self.assertEqual(1, len(self.verification.list_records("alice", "holder")))

    def test_permissions_and_field_validation(self):
        # 只有核验方角色能登记申请
        with self.assertRaises(ApiError) as ctx:
            self.verification.create_request("alice", "holder", self.credential["id"], "自用", ["name"], 30)
        self.assertEqual(403, ctx.exception.status)
        # 拟看字段不能超出模板、不能重复、用途不能为空
        with self.assertRaises(ApiError):
            self.verification.create_request("bank-1", "verifier", self.credential["id"], "核验", ["name", "salary"], 30)
        with self.assertRaises(ApiError):
            self.verification.create_request("bank-1", "verifier", self.credential["id"], "核验", ["name", "name"], 30)
        with self.assertRaises(ApiError):
            self.verification.create_request("bank-1", "verifier", self.credential["id"], "  ", ["name"], 30)

        request = self._request()
        # 持有人以外的角色不能同意；别的持有人也不能同意
        with self.assertRaises(ApiError):
            self.verification.consent("bank-1", "verifier", request["id"])
        with self.assertRaises(ApiError) as ctx:
            self.verification.consent("mallory", "holder", request["id"])
        self.assertEqual(403, ctx.exception.status)
        # 别的核验方不能兑付
        token = self._consent(request["id"])["one_time_token"]
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem("bank-2", "verifier", token)
        self.assertEqual(403, ctx.exception.status)
        # 持有人不能撤回别人的申请
        with self.assertRaises(ApiError) as ctx:
            self.verification.withdraw("mallory", "holder", request["id"])
        self.assertEqual(403, ctx.exception.status)


if __name__ == "__main__":
    unittest.main()
