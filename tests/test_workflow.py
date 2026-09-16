"""Exercise the connector workflow with synthetic email and in-memory clients."""

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "FunctionApp"))

from JoeSandboxDefenderO365.lib.models import EmailEvidence, Submission
from JoeSandboxDefenderO365.workflow import process_alerts


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.email = EmailEvidence(
            raw_eml=b"From: sender@example.test\r\n\r\nsynthetic\r\n",
            sha256="a" * 64,
            filename="test.eml",
            mailbox_user="recipient@example.test",
            internet_message_id="<test@example.test>",
            graph_message_id="message-1",
            alert_ids={"alert-1", "alert-2"},
            incident_ids={"incident-1"},
        )
        self.analysis = {"webid": "42", "detection": "malicious", "score": 90}
        self.defender = Mock()
        self.defender.get_alerts.return_value = [{"id": "alert-1"}, {"id": "alert-2"}]
        self.defender.get_email_evidences.return_value = [self.email]
        self.defender.indicators_enabled_for.return_value = False
        self.joe = Mock()
        self.joe.config = SimpleNamespace(base_url="https://joe.example.test/", resubmit=False)
        self.joe.parse_analysis.return_value = {}
        self.joe.wait_submissions.return_value = []
        self.joe.get_most_relevant_analysis.return_value = self.analysis

    def run_cycle(self):
        return process_alerts("2026-09-16T00:00:00Z", self.defender, self.joe)

    def previous_submission(self, status):
        self.email.comments_by_alert = {"alert-1": {
            "Raw EML submitted to Joe Sandbox.\n"
            f"EML SHA256: {self.email.sha256}\n"
            "Submission ID: 123\nJoe Sandbox tag: MDO-test"
        }}
        self.joe.get_submission_info.return_value = {"status": status}

    def test_new_email_is_submitted_once_then_enriched(self):
        submission = Submission("123", self.email, "MDO-test")
        self.joe.submit_raw_email.return_value = submission
        self.joe.wait_submissions.return_value = [(submission, {"status": "finished"})]
        counts = self.run_cycle()
        self.joe.submit_raw_email.assert_called_once_with(self.email)
        self.joe.wait_submissions.assert_called_once_with([submission])
        self.assertEqual((1, 1), (counts["submitted"], counts["finished"]))
        comments = self.defender.add_alert_comment.call_args_list
        self.assertEqual(2, len(comments))
        self.assertIn("Submission ID: 123", comments[0].args[1])
        self.assertIn("https://joe.example.test/analysis/42", comments[1].args[1])
        self.assertIs(self.email, comments[1].args[0])

    def test_pending_submission_is_recovered_without_resubmitting(self):
        self.previous_submission("running")
        counts = self.run_cycle()
        self.joe.get_submission_info.assert_called_once_with("123")
        self.joe.submit_raw_email.assert_not_called()
        self.joe.get_analysis.assert_not_called()
        self.defender.add_incident_tags.assert_not_called()
        self.assertEqual(1, counts["previous_submissions"])

    def test_finished_prior_submission_uses_joe_selected_analysis(self):
        self.previous_submission("finished")
        counts = self.run_cycle()
        self.joe.get_most_relevant_analysis.assert_called_once_with({"status": "finished"})
        self.joe.submit_raw_email.assert_not_called()
        self.assertEqual(1, counts["existing_analyses"])
        self.defender.add_incident_tags.assert_called_once_with(
            {"incident-1"}, ["#Joe Sandbox Malicious"]
        )

    def test_existing_hash_result_is_reused(self):
        self.joe.parse_analysis.return_value = self.analysis
        counts = self.run_cycle()
        self.joe.get_analysis.assert_called_once_with(self.email.sha256)
        self.joe.submit_raw_email.assert_not_called()
        self.assertEqual(1, counts["existing_analyses"])

    def test_resubmit_setting_bypasses_hash_search(self):
        self.joe.config.resubmit = True
        self.joe.submit_raw_email.return_value = Submission("123", self.email, "MDO-test")
        counts = self.run_cycle()
        self.joe.get_analysis.assert_not_called()
        self.joe.submit_raw_email.assert_called_once_with(self.email)
        self.assertEqual(1, counts["submitted"])

    def test_ioc_failure_still_adds_result_comments(self):
        self.joe.parse_analysis.return_value = self.analysis
        self.defender.indicators_enabled_for.return_value = True
        self.joe.get_indicators.side_effect = RuntimeError("synthetic IOC failure")
        with self.assertLogs(level="ERROR"):
            counts = self.run_cycle()
        self.assertEqual(1, counts["indicators_failed"])
        self.defender.add_alert_comment.assert_called_once()
        self.defender.add_incident_comments.assert_called_once()


if __name__ == "__main__":
    unittest.main()
