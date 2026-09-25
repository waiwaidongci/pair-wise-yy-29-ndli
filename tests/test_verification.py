import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import CredentialService
from occupancy import OccupancyRegistry
from persistence import ApiError, Store, iso, now
from verification import VerificationService


class OneTimeVerificationFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "test.db")
        self.credentials = CredentialService(self.store)
        self.verification = VerificationService(self.store, OccupancyRegistry())
        self.credentials.rotate_key("issuer-a", "issuer", "issuer-a")
        template = self.credentials.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "degree", "required": True}, {"name": "gpa", "required": False}],
            365,
        )
        self.credential = self.credentials.issue(
            "issuer-a", "issuer", template["id"], "alice",
            {"name": "Alice", "degree": "BSc", "gpa": "3.8"}, "issue-1",
        )
        self.credential_id = self.credential["id"]

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _approved(self, verifier="bank-a", fields=None, ttl=None):
        fields = fields or ["name", "degree", "gpa"]
        req = self.verification.create_request(
            verifier, "verifier", self.credential_id, "入职背景调查", fields
        )
        approved = self.verification.approve_request(
            "alice", "holder", req["id"], None, ttl
        )
        return req, approved

    def test_full_flow_request_approve_redeem_once(self):
        req, approved = self._approved()
        self.assertEqual("approved", approved["status"])
        self.assertTrue(approved["voucher_token"])
        # 原始令牌不入库，库里只保存它的哈希
        stored = self.store.conn.execute(
            "SELECT voucher_token_hash FROM verification_requests WHERE id=?", (req["id"],)
        ).fetchone()["voucher_token_hash"]
        self.assertTrue(stored)
        self.assertNotEqual(stored, approved["voucher_token"])

        result = self.verification.redeem_voucher(
            "bank-a", "verifier", approved["voucher_token"]
        )
        self.assertTrue(result["valid"])
        self.assertEqual("valid", result["status"])
        self.assertEqual("Alice", result["claims"]["name"])
        self.assertEqual(["name", "degree", "gpa"], result["fields"])
        self.assertEqual(self.credential_id, result["credential_id"])

        # 第二次取用同一凭证：立即拒绝
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem_voucher("bank-a", "verifier", approved["voucher_token"])
        self.assertEqual(410, ctx.exception.status)
        self.assertIn("已使用", ctx.exception.message)

        # 申请已标记 consumed
        got = self.verification.get_request("alice", "holder", req["id"])
        self.assertEqual("consumed", got["status"])
        self.assertIsNotNone(got["consumed_at"])

        # 留痕：持有人能看到谁、为什么、看过哪些字段
        records = self.verification.list_records("alice", "holder")
        self.assertEqual(1, len(records))
        self.assertEqual("bank-a", records[0]["verifier_id"])
        self.assertEqual("入职背景调查", records[0]["purpose"])
        self.assertEqual(["name", "degree", "gpa"], records[0]["fields"])

    def test_approved_fields_can_be_reduced_and_redeem_fields_must_be_within(self):
        req = self.verification.create_request(
            "bank-a", "verifier", self.credential_id, "开户", ["name", "degree", "gpa"]
        )
        approved = self.verification.approve_request(
            "alice", "holder", req["id"], ["name", "degree"]
        )
        self.assertEqual(["name", "degree"], approved["approved_fields"])

        # 取用时只能看同意范围以内的字段
        result = self.verification.redeem_voucher(
            "bank-a", "verifier", approved["voucher_token"], ["name"]
        )
        self.assertEqual(["name"], result["fields"])
        self.assertNotIn("gpa", result["claims"])

        # 同意阶段不能放行申请以外的字段
        req2 = self.verification.create_request(
            "bank-b", "verifier", self.credential_id, "开户", ["name"]
        )
        with self.assertRaises(ApiError) as ctx:
            self.verification.approve_request("alice", "holder", req2["id"], ["name", "gpa"])
        self.assertEqual(400, ctx.exception.status)

    def test_redeem_fields_outside_approved_scope_rejected_and_voucher_still_usable(self):
        _, approved = self._approved(fields=["name", "degree"])
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem_voucher(
                "bank-a", "verifier", approved["voucher_token"], ["name", "gpa"]
            )
        self.assertEqual(403, ctx.exception.status)
        # 超范围拒绝不消耗一次性凭证：随后合规取用成功
        result = self.verification.redeem_voucher(
            "bank-a", "verifier", approved["voucher_token"], ["name"]
        )
        self.assertEqual(["name"], result["fields"])

    def test_expired_voucher_rejected(self):
        _, approved = self._approved(ttl=30)
        future = iso(now() + timedelta(seconds=31))
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem_voucher(
                "bank-a", "verifier", approved["voucher_token"], None, at=future
            )
        self.assertEqual(410, ctx.exception.status)
        self.assertIn("过期", ctx.exception.message)
        # 过期后落盘状态
        got = self.verification.get_request("alice", "holder", approved["request_id"])
        self.assertEqual("expired", got["status"])

    def test_withdraw_before_use_invalidates_after_consent_records_kept(self):
        req, approved = self._approved()
        # 已成功核验，留痕存在
        self.verification.redeem_voucher("bank-a", "verifier", approved["voucher_token"])
        # 已用申请不能撤回，记录继续保留
        with self.assertRaises(ApiError) as ctx:
            self.verification.withdraw_consent("alice", "holder", req["id"])
        self.assertEqual(409, ctx.exception.status)
        self.assertEqual(1, len(self.verification.list_records("alice", "holder")))

        # 未同意的申请可直接撤回
        pending = self.verification.create_request(
            "bank-b", "verifier", self.credential_id, "租房", ["name"]
        )
        withdrawn = self.verification.withdraw_consent("alice", "holder", pending["id"])
        self.assertEqual("withdrawn", withdrawn["status"])
        # 撤回后核验方无法取用（待同意本来就没有凭证令牌行）
        # —— 待同意撤回路径：status=withdrawn

        # 已同意但未使用的申请撤回后令牌作废
        req2 = self.verification.create_request(
            "bank-c", "verifier", self.credential_id, "签证", ["name", "degree"]
        )
        approved2 = self.verification.approve_request("alice", "holder", req2["id"])
        self.verification.withdraw_consent("alice", "holder", req2["id"])
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem_voucher("bank-c", "verifier", approved2["voucher_token"])
        self.assertEqual(410, ctx.exception.status)
        self.assertIn("撤回", ctx.exception.message)
        # 已有记录仍在
        self.assertEqual(1, len(self.verification.list_records("alice", "holder")))

    def test_request_validation_and_permissions(self):
        # 用途不能为空
        with self.assertRaises(ApiError) as ctx:
            self.verification.create_request(
                "bank-a", "verifier", self.credential_id, "  ", ["name"]
            )
        self.assertEqual(400, ctx.exception.status)
        # 字段必须在模板里
        with self.assertRaises(ApiError) as ctx:
            self.verification.create_request(
                "bank-a", "verifier", self.credential_id, "入职", ["name", "ssn"]
            )
        self.assertEqual(400, ctx.exception.status)
        # 只有 verifier 能登记
        with self.assertRaises(ApiError):
            self.verification.create_request(
                "alice", "holder", self.credential_id, "自查", ["name"]
            )
        # 持有人只能同意自己的凭证申请
        other = self.verification.create_request(
            "bank-a", "verifier", self.credential_id, "入职", ["name"]
        )
        with self.assertRaises(ApiError) as ctx:
            self.verification.approve_request("bob", "holder", other["id"])
        self.assertEqual(403, ctx.exception.status)
        # 凭证不属于当前核验方
        approved_req, approved = self._approved()
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem_voucher("bank-other", "verifier", approved["voucher_token"])
        self.assertEqual(403, ctx.exception.status)
        # 伪造令牌
        with self.assertRaises(ApiError) as ctx:
            self.verification.redeem_voucher("bank-a", "verifier", "not-a-real-token")
        self.assertEqual(404, ctx.exception.status)

    def test_pending_request_expires_after_request_ttl(self):
        from verification import REQUEST_TTL
        req = self.verification.create_request(
            "bank-a", "verifier", self.credential_id, "入职", ["name"]
        )
        # 把登记期限改到过去，模拟申请一直未获同意而失效
        past = iso(now() - timedelta(seconds=1))
        with self.store.conn:
            self.store.conn.execute(
                "UPDATE verification_requests SET expires_at=? WHERE id=?", (past, req["id"])
            )
        # 过期申请不能同意
        with self.assertRaises(ApiError) as ctx:
            self.verification.approve_request("alice", "holder", req["id"], None, None)
        self.assertEqual(409, ctx.exception.status)
        self.assertIn("expired", ctx.exception.message)
        # REQUEST_TTL 常量本身保持 7 天量级
        self.assertGreaterEqual(REQUEST_TTL, timedelta(days=1))

    def test_concurrent_redeem_only_one_succeeds(self):
        req, approved = self._approved(ttl=86400)
        token = approved["voucher_token"]
        outcomes: list[str] = []
        barrier = threading.Barrier(4)

        def redeem() -> None:
            barrier.wait()
            try:
                self.verification.redeem_voucher("bank-a", "verifier", token)
                outcomes.append("ok")
            except ApiError as exc:
                outcomes.append(f"error:{exc.status}")

        threads = [threading.Thread(target=redeem) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(1, outcomes.count("ok"), outcomes)
        self.assertEqual(3, sum(1 for o in outcomes if o.startswith("error:")), outcomes)
        # 只留一条核验记录
        records = self.verification.list_records("alice", "holder")
        self.assertEqual(1, len(records))
        self.assertEqual("consumed", self.verification.get_request("alice", "holder", req["id"])["status"])

    def test_withdraw_races_with_redeem_only_one_wins(self):
        _, approved = self._approved(ttl=86400)
        token = approved["voucher_token"]
        request_id = approved["id"]
        result = {}
        start = threading.Event()

        def redeem() -> None:
            start.wait()
            try:
                self.verification.redeem_voucher("bank-a", "verifier", token)
                result["redeem"] = "ok"
            except ApiError as exc:
                result["redeem"] = f"error:{exc.status}"

        def withdraw() -> None:
            start.wait()
            try:
                self.verification.withdraw_consent("alice", "holder", request_id)
                result["withdraw"] = "ok"
            except ApiError as exc:
                result["withdraw"] = f"error:{exc.status}"

        t1 = threading.Thread(target=redeem)
        t2 = threading.Thread(target=withdraw)
        t1.start()
        t2.start()
        start.set()
        t1.join()
        t2.join()

        final_status = self.verification.get_request("alice", "holder", request_id)["status"]
        if result["redeem"] == "ok":
            self.assertEqual("consumed", final_status)
            self.assertTrue(result["withdraw"].startswith("error"))
            self.assertEqual(1, len(self.verification.list_records("alice", "holder")))
        else:
            self.assertEqual("withdrawn", final_status)
            self.assertEqual("ok", result["withdraw"])
            self.assertEqual(0, len(self.verification.list_records("alice", "holder")))

    def test_revoked_credential_still_delivers_one_time_result_marked_invalid(self):
        _, approved = self._approved(ttl=86400)
        self.credentials.revoke("issuer-a", "issuer", self.credential_id, "学业资格不符")
        result = self.verification.redeem_voucher("bank-a", "verifier", approved["voucher_token"])
        self.assertFalse(result["valid"])
        self.assertEqual("revoked", result["status"])
        self.assertEqual("学业资格不符", result["reason"])
        # 凭证被撤也不改变一次性语义
        with self.assertRaises(ApiError):
            self.verification.redeem_voucher("bank-a", "verifier", approved["voucher_token"])


if __name__ == "__main__":
    unittest.main()
