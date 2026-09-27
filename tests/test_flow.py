import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import DomainError, VulnerabilityDB

class VulnerabilityFlowTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所"); self.coord=self.db.add_user("协调员","coordinator","响应中心"); self.maint=self.db.add_user("维护者","maintainer","项目组"); self.outsider=self.db.add_user("旁观者","reporter","外部")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def _advance_to_fixing(self, plan="增加鉴权前置校验", target_date="2026-10-20"):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_member(self.report,self.coord,"coordinator",self.coord)
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.set_fix_plan(self.report,self.maint,plan,target_date)
    def _advance_to_resolved(self):
        self._advance_to_fixing()
        self.db.submit_fix_completion(self.report,self.maint,"补丁已合并并通过回归测试")
        self.db.approve_fix_acceptance(self.report,self._latest_acceptance()["id"],self.coord,"验证通过")
        self.db.set_status(self.report,"resolved",self.coord)
        self.db.create_advisory_draft(self.report,"受影响版本 3.2.0。请升级到 3.2.1。",self.coord)
    def _latest_acceptance(self):
        return self.db.get_report_for_user(self.report,self.coord)["fix_acceptances"][-1]
    def test_full_disclosure_flow_and_early_publish_rejected(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"提前披露"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        advisory=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",advisory["status"])
        self.assertTrue(self.db.notifications_for(self.maint))
    def test_denies_outsider_and_duplicate_report(self):
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.get_report_for_user(self.report,self.outsider)
        with self.assertRaisesRegex(DomainError,"重复"):
            self.db.create_report("重复问题",self.product,self.reporter,"相同版本的另一份报告","2026-11-01",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_evidence(self.report,"协调材料","secret","coordinator",self.coord)
        visible=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],visible["evidence"])

    def test_resolved_requires_maintainer_submission_and_coordinator_approval(self):
        self._advance_to_fixing()
        with self.assertRaisesRegex(DomainError,"尚未提交"):
            self.db.set_status(self.report,"resolved",self.coord)
        acceptance_id=self.db.submit_fix_completion(self.report,self.maint,"补丁已合并")
        with self.assertRaisesRegex(DomainError,"等待协调员验收"):
            self.db.set_status(self.report,"resolved",self.coord)
        with self.assertRaisesRegex(DomainError,"只有协调员"):
            self.db.approve_fix_acceptance(self.report,acceptance_id,self.maint)
        self.db.approve_fix_acceptance(self.report,acceptance_id,self.coord,"确认通过")
        self.db.set_status(self.report,"resolved",self.coord)
        payload=self.db.get_report_for_user(self.report,self.coord)
        record=next(a for a in payload["fix_acceptances"] if a["id"]==acceptance_id)
        self.assertEqual("approved",record["status"])
        self.assertEqual(1,record["plan_version"])
        self.assertEqual(self.coord,record["coordinator_id"])
        self.assertEqual("增加鉴权前置校验",record["plan_snapshot"])
    def test_plan_change_invalidates_acceptance_and_notifies_coordinator(self):
        self._advance_to_fixing()
        first=self.db.submit_fix_completion(self.report,self.maint,"补丁已合并")
        self.db.approve_fix_acceptance(self.report,first,self.coord,"确认通过")
        before=len(self.db.notifications_for(self.coord))
        # 计划内容或目标日期未变，旧验收继续有效
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验","2026-10-20")
        self.assertEqual("approved",self._latest_acceptance()["status"])
        # 修改目标日期：旧验收失效并通知协调员，不能再直接解决
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验","2026-10-25")
        payload=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual(2,payload["fix_plan"]["version"])
        old=next(a for a in payload["fix_acceptances"] if a["id"]==first)
        self.assertEqual("invalidated",old["status"])
        self.assertIn("修改了修复计划",old["invalidated_reason"])
        self.assertGreater(len(self.db.notifications_for(self.coord)),before)
        with self.assertRaisesRegex(DomainError,"尚未提交"):
            self.db.set_status(self.report,"resolved",self.coord)
        with self.assertRaisesRegex(DomainError,"已失效"):
            self.db.approve_fix_acceptance(self.report,first,self.coord)
        # 重新提交并验收新版本后才能解决，历史记录完整保留
        second=self.db.submit_fix_completion(self.report,self.maint,"按新日期完成")
        self.db.approve_fix_acceptance(self.report,second,self.coord,"新版本确认通过")
        self.db.set_status(self.report,"resolved",self.coord)
        records=self.db.get_report_for_user(self.report,self.coord)["fix_acceptances"]
        self.assertEqual(["invalidated","approved"],[a["status"] for a in records])
        self.assertEqual([1,2],[a["plan_version"] for a in records])
    def test_reopen_to_fixing_invalidates_acceptance(self):
        self._advance_to_resolved()
        self.db.set_status(self.report,"fixing",self.coord,"回归发现遗留问题")
        record=self._latest_acceptance()
        self.assertEqual("invalidated",record["status"])
        with self.assertRaisesRegex(DomainError,"尚未提交"):
            self.db.set_status(self.report,"resolved",self.coord)

if __name__=="__main__": unittest.main()
