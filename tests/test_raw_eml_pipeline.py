"""Static, network-free tests for the raw EML submission boundary."""

import logging
from pathlib import Path
import sys
import types
import unittest


FUNCTION_APP = Path(__file__).resolve().parents[1] / "FunctionApp"
sys.path.insert(0, str(FUNCTION_APP))

# The production package is installed by Azure. A narrow stub keeps these tests
# network-free while exercising our wrapper around that package.
jbxapi = types.ModuleType("jbxapi")


class JoeApiError(Exception):
    pass


jbxapi.ConnectionError = JoeApiError
jbxapi.InvalidApiKeyError = JoeApiError
jbxapi.InvalidParameterError = JoeApiError
jbxapi.PermissionError = JoeApiError
jbxapi.ServerOfflineError = JoeApiError
jbxapi.JoeSandbox = object
sys.modules.setdefault("jbxapi", jbxapi)

from JoeSandboxDefenderO365.lib.joesandbox import JoeSandbox  # noqa: E402
from JoeSandboxDefenderO365.lib.iocs import parse_irjson_indicators  # noqa: E402
from JoeSandboxDefenderO365.lib.microsoft_defender import (  # noqa: E402
    MicrosoftDefender,
)
from JoeSandboxDefenderO365.lib.models import EmailEvidence, Indicator  # noqa: E402


class FakeResponse:
    def __init__(self, *, payload=None, content=b""):
        self._payload = payload or {}
        self.content = content

    def json(self):
        return self._payload


class RawEmailTests(unittest.TestCase):
    def test_graph_mime_bytes_are_returned_unchanged(self):
        raw_eml = (
            b"Received: by test.invalid\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"synthetic test body\r\n"
        )
        client = object.__new__(MicrosoftDefender)
        client.log = logging.getLogger("test")
        client.graph_headers = {"Authorization": "Bearer synthetic"}
        client.config = types.SimpleNamespace(
            graph_url="https://graph.microsoft.com/v1.0"
        )
        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            if url.endswith("/messages"):
                return FakeResponse(payload={"value": [{"id": "graph-message-id"}]})
            self.assertTrue(url.endswith("/messages/graph-message-id/$value"))
            return FakeResponse(content=raw_eml)

        client.retry_request = fake_request
        result = client.download_raw_email("user@example.test", "<message@test>")

        self.assertEqual((raw_eml, "graph-message-id"), result)
        self.assertEqual(2, len(calls))
        self.assertEqual("application/octet-stream", calls[1][2]["headers"]["Accept"])

    def test_duplicate_alerts_produce_one_raw_email(self):
        raw_eml = b"From: sender@example.test\r\n\r\nsynthetic\r\n"
        client = object.__new__(MicrosoftDefender)
        client.log = logging.getLogger("test")
        client.download_raw_email = lambda *_: (raw_eml, "graph-id")
        message_evidence = {
            "@odata.type": "#microsoft.graph.security.analyzedMessageEvidence",
            "recipientEmailAddress": "user@example.test",
            "internetMessageId": "<same@test>",
        }
        alerts = [
            {
                "id": "alert-1",
                "incidentId": "incident-1",
                "evidence": [message_evidence],
                "comments": [],
            },
            {
                "id": "alert-2",
                "incidentId": "incident-1",
                "evidence": [message_evidence],
                "comments": [],
            },
        ]

        evidences = client.get_email_evidences(alerts)

        self.assertEqual(1, len(evidences))
        self.assertEqual({"alert-1", "alert-2"}, evidences[0].alert_ids)
        self.assertEqual(raw_eml, evidences[0].raw_eml)
        self.assertTrue(evidences[0].filename.endswith(".eml"))

    def test_joe_wrapper_submits_only_the_complete_eml_sample(self):
        raw_eml = b"MIME-Version: 1.0\r\n\r\nsynthetic\r\n"
        evidence = EmailEvidence(
            raw_eml=raw_eml,
            sha256="a" * 64,
            filename="mdo-aaaaaaaaaaaaaaaaaaaa.eml",
            mailbox_user="user@example.test",
            internet_message_id="<id@test>",
            graph_message_id="graph-id",
            alert_ids={"alert-1"},
        )

        class Api:
            def __init__(self):
                self.calls = []

            def submit_sample(self, *, sample, params):
                self.calls.append((sample, params))
                return {"submission_id": 12345}

        wrapper = object.__new__(JoeSandbox)
        wrapper.log = logging.getLogger("test")
        wrapper.api = Api()

        submission = wrapper.submit_raw_email(evidence)

        self.assertEqual("12345", submission.submission_id)
        self.assertEqual(1, len(wrapper.api.calls))
        sample, params = wrapper.api.calls[0]
        self.assertEqual(raw_eml, sample.read())
        self.assertEqual(evidence.filename, sample.name)
        self.assertEqual("Defender-O365-Raw-EML", params["tags"][0])
        self.assertRegex(params["tags"][1], r"^MDO-[0-9a-f]{32}$")
        self.assertEqual(params["tags"][1], submission.analysis_tag)
        self.assertIn(submission.analysis_tag, params["comments"])
        self.assertFalse(hasattr(wrapper, "submit_url"))

        second_submission = wrapper.submit_raw_email(evidence)
        second_params = wrapper.api.calls[1][1]
        self.assertNotEqual(
            submission.analysis_tag,
            second_submission.analysis_tag,
        )
        self.assertEqual(second_params["tags"][1], second_submission.analysis_tag)

    def test_prior_submission_comment_makes_polling_overlap_idempotent(self):
        evidence = EmailEvidence(
            raw_eml=b"synthetic",
            sha256="b" * 64,
            filename="mdo-bbbbbbbbbbbbbbbbbbbb.eml",
            mailbox_user="user@example.test",
            internet_message_id="<id@test>",
            graph_message_id="graph-id",
            comments_by_alert={
                "alert-1": {
                    "Raw EML submitted to Joe Sandbox.\n"
                    f"EML SHA256: {'b' * 64}\n"
                    "Submission ID: 98765"
                }
            },
        )

        self.assertEqual("98765", evidence.previous_submission_id())

    def test_prior_submission_comment_recovers_unique_joe_tag(self):
        evidence = EmailEvidence(
            raw_eml=b"synthetic",
            sha256="b" * 64,
            filename="mdo-bbbbbbbbbbbbbbbbbbbb.eml",
            mailbox_user="user@example.test",
            internet_message_id="<id@test>",
            graph_message_id="graph-id",
            comments_by_alert={
                "alert-1": {
                    "Raw EML submitted to Joe Sandbox.\n"
                    f"EML SHA256: {'b' * 64}\n"
                    "Submission ID: 98765\n"
                    f"Joe Sandbox tag: MDO-{'c' * 32}"
                }
            },
        )

        self.assertEqual(("98765", f"MDO-{'c' * 32}"), evidence.previous_submission())

    def test_submission_info_uses_joe_most_relevant_analysis(self):
        submission_info = {
            "status": "finished",
            "most_relevant_analysis": {"webid": "interesting-analysis"},
            "analyses": [
                {"webid": "eml-container"},
                {"webid": "interesting-analysis"},
            ],
        }

        self.assertEqual(
            "interesting-analysis",
            JoeSandbox.most_relevant_web_id(submission_info),
        )
        self.assertEqual(
            "",
            JoeSandbox.most_relevant_web_id(
                {"status": "finished", "analyses": [{"webid": "first"}]}
            ),
        )

        wrapper = object.__new__(JoeSandbox)
        wrapper.get_analysis_info = lambda web_id: {
            "webid": web_id,
            "detection": "malicious",
            "score": 88,
        }
        self.assertEqual(
            {
                "webid": "interesting-analysis",
                "detection": "malicious",
                "score": 88,
            },
            wrapper.get_most_relevant_analysis(submission_info),
        )

    def test_irjson_extracts_only_malicious_defender_indicators(self):
        report = {
            "analysis": {
                "contacted": {
                    "domains": {
                        "domain": [
                            {"name": "Evil.Example.", "malicious": True},
                            {"name": "clean.example", "malicious": False},
                        ]
                    },
                    "ips": {
                        "ip": [
                            {"$": "2001:0db8::1", "@malicious": "true"},
                            {"$": "192.0.2.0/24", "@malicious": "true"},
                        ]
                    },
                    "urls": {
                        "url": [
                            {"name": "https://evil.example/path", "malicious": 1},
                            {"name": "file:///tmp/test", "malicious": True},
                        ]
                    },
                },
                "dropped": {
                    "file": [
                        {
                            "name": "synthetic.bin",
                            "malicious": True,
                            "md5": "a" * 32,
                            "sha1": "b" * 40,
                            "sha256": "c" * 64,
                        },
                        {
                            "name": "duplicate.bin",
                            "malicious": True,
                            "sha256": "c" * 64,
                        },
                        {
                            "name": "clean.bin",
                            "malicious": False,
                            "sha256": "d" * 64,
                        },
                    ]
                },
            }
        }

        indicators = parse_irjson_indicators(report)

        self.assertEqual(
            {
                ("DomainName", "evil.example"),
                ("IpAddress", "2001:db8::1"),
                ("Url", "https://evil.example/path"),
                ("FileMd5", "a" * 32),
                ("FileSha1", "b" * 40),
                ("FileSha256", "c" * 64),
            },
            {(item.indicator_type, item.value) for item in indicators},
        )

    def test_joe_downloads_irjson_for_indicator_extraction(self):
        class Api:
            def __init__(self):
                self.calls = []

            def analysis_download(self, web_id, **kwargs):
                self.calls.append((web_id, kwargs))
                return (
                    "report.json",
                    b'{"analysis":{"contacted":{"domains":{"domain":'
                    b'[{"name":"evil.example","malicious":true}]}}}}',
                )

        wrapper = object.__new__(JoeSandbox)
        wrapper.log = logging.getLogger("test")
        wrapper.api = Api()

        indicators = wrapper.get_indicators("analysis-web-id")

        self.assertEqual(
            [("analysis-web-id", {"type": "irjsonfixed"})], wrapper.api.calls
        )
        self.assertEqual([Indicator("DomainName", "evil.example")], indicators)

    def test_defender_imports_new_indicators_in_one_batch(self):
        client = object.__new__(MicrosoftDefender)
        client.log = logging.getLogger("test")
        client.defender_headers = {"Authorization": "Bearer synthetic"}
        client.config = types.SimpleNamespace(
            create_indicators=True,
            indicator_verdicts=("malicious", "suspicious"),
            indicator_expiration_days=30,
            malicious_network_action="Block",
            suspicious_network_action="Audit",
            malicious_file_action="Block",
            suspicious_file_action="Audit",
            indicator_generate_alert=False,
            defender_api_url="https://api.security.microsoft.com/api",
        )
        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            if method == "GET":
                return FakeResponse(payload={"value": []})
            values = [
                {
                    "indicator": item["indicatorValue"],
                    "isFailed": False,
                    "failureReason": None,
                }
                for item in kwargs["json"]["Indicators"]
            ]
            return FakeResponse(payload={"value": values})

        client.retry_request = fake_request
        evidence = EmailEvidence(
            raw_eml=b"synthetic",
            sha256="e" * 64,
            filename="mdo-synthetic.eml",
            mailbox_user="user@example.test",
            internet_message_id="<id@test>",
            graph_message_id="graph-id",
            alert_ids={"alert-1"},
        )

        result = client.create_indicators(
            [
                Indicator("Url", "https://evil.example/path"),
                Indicator("FileSha256", "f" * 64),
            ],
            {"webid": "analysis-web-id", "detection": "suspicious"},
            evidence,
        )

        self.assertEqual((2, 0), result)
        self.assertEqual(2, len(calls))
        self.assertEqual("GET", calls[0][0])
        self.assertEqual("POST", calls[1][0])
        self.assertEqual(
            "https://api.security.microsoft.com/api/indicators/import", calls[1][1]
        )
        payloads = calls[1][2]["json"]["Indicators"]
        self.assertEqual({"Audit"}, {item["action"] for item in payloads})
        self.assertTrue(all(item["generateAlert"] for item in payloads))

    def test_defender_does_not_overwrite_an_existing_indicator(self):
        client = object.__new__(MicrosoftDefender)
        client.log = logging.getLogger("test")
        client.defender_headers = {"Authorization": "Bearer synthetic"}
        client._existing_indicator_keys = {("DomainName", "existing.example")}
        client.config = types.SimpleNamespace(
            create_indicators=True,
            indicator_verdicts=("malicious",),
            defender_api_url="https://api.security.microsoft.com/api",
        )
        client.retry_request = lambda *args, **kwargs: self.fail(
            "No API request expected for an existing indicator"
        )

        result = client.create_indicators(
            [Indicator("DomainName", "EXISTING.EXAMPLE")],
            {"webid": "analysis-web-id", "detection": "malicious"},
            EmailEvidence(
                raw_eml=b"synthetic",
                sha256="e" * 64,
                filename="mdo-synthetic.eml",
                mailbox_user="user@example.test",
                internet_message_id="<id@test>",
                graph_message_id="graph-id",
            ),
        )

        self.assertEqual((0, 0), result)

    def test_incident_comment_is_added_once(self):
        client = object.__new__(MicrosoftDefender)
        client.log = logging.getLogger("test")
        client.graph_headers = {"Authorization": "Bearer synthetic"}
        client.config = types.SimpleNamespace(
            graph_url="https://graph.microsoft.com/v1.0",
            add_comments_to_incident=True,
        )
        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            if method == "GET":
                return FakeResponse(payload={"comments": []})
            return FakeResponse(payload={"value": []})

        client.retry_request = fake_request

        client.add_incident_comments({"incident-1"}, "Synthetic result")
        client.add_incident_comments({"incident-1"}, "Synthetic result")

        self.assertEqual(2, len(calls))
        self.assertEqual("GET", calls[0][0])
        self.assertEqual("POST", calls[1][0])
        self.assertTrue(calls[1][1].endswith("/incidents/incident-1/comments"))
        self.assertEqual("Synthetic result", calls[1][2]["json"]["comment"])


if __name__ == "__main__":
    unittest.main()
