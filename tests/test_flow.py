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
    def _advance_to_fixing(self):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验", "2026-10-20")
    def _advance_to_resolved(self):
        self._advance_to_fixing()
        acceptance=self.db.submit_fix_acceptance(self.report,self.maint,"补丁已合并")
        self.db.confirm_fix_acceptance(self.report,acceptance,self.coord)
        self.db.set_status(self.report,"resolved",self.coord)
        self.db.create_advisory_draft(self.report,"受影响版本 3.2.0。请升级到 3.2.1。",self.coord)
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
    def test_resolution_requires_confirmed_acceptance(self):
        self._advance_to_fixing()
        with self.assertRaisesRegex(DomainError,"验收"):
            self.db.set_status(self.report,"resolved",self.coord)
        acceptance=self.db.submit_fix_acceptance(self.report,self.maint,"补丁已合并并发布 3.2.1")
        with self.assertRaisesRegex(DomainError,"验收"):
            self.db.set_status(self.report,"resolved",self.coord)
        self.db.confirm_fix_acceptance(self.report,acceptance,self.coord)
        self.db.set_status(self.report,"resolved",self.coord)
        report=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("resolved",report["status"])
        self.assertEqual("confirmed",report["acceptances"][0]["status"])
        self.assertEqual(self.coord,report["acceptances"][0]["confirmed_by"])
        self.assertEqual(1,report["acceptances"][0]["plan_revision"])
    def test_plan_change_invalidates_acceptance_and_notifies(self):
        self._advance_to_fixing()
        first=self.db.submit_fix_acceptance(self.report,self.maint,"第一版完成")
        self.db.confirm_fix_acceptance(self.report,first,self.coord)
        self.db.set_fix_plan(self.report,self.maint,"改为整体升级鉴权模块","2026-11-05")
        report=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("invalidated",report["acceptances"][0]["status"])
        self.assertEqual(2,report["fix_plan"]["revision"])
        with self.assertRaisesRegex(DomainError,"验收"):
            self.db.set_status(self.report,"resolved",self.coord)
        notes=[n for n in self.db.notifications_for(self.coord) if n["kind"]=="acceptance"]
        self.assertTrue(any("失效" in n["message"] for n in notes))
        second=self.db.submit_fix_acceptance(self.report,self.maint,"第二版完成")
        self.db.confirm_fix_acceptance(self.report,second,self.coord)
        self.db.set_fix_plan(self.report,self.maint,"改为整体升级鉴权模块","2026-11-05")
        self.db.set_status(self.report,"resolved",self.coord)
        report=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("resolved",report["status"])
        self.assertEqual(2,len(report["acceptances"]))
        self.assertEqual(["invalidated","confirmed"],[a["status"] for a in report["acceptances"]])
    def test_acceptance_permissions_and_duplicates(self):
        self._advance_to_fixing()
        with self.assertRaisesRegex(DomainError,"维护者"):
            self.db.submit_fix_acceptance(self.report,self.coord,"协调员不能提交")
        acceptance=self.db.submit_fix_acceptance(self.report,self.maint,"完成")
        with self.assertRaisesRegex(DomainError,"待确认"):
            self.db.submit_fix_acceptance(self.report,self.maint,"重复提交")
        with self.assertRaisesRegex(DomainError,"协调员"):
            self.db.confirm_fix_acceptance(self.report,acceptance,self.maint)

if __name__=="__main__": unittest.main()
