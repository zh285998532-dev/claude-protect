import io
import ssl
import unittest
from unittest.mock import MagicMock, patch

from claude_protect.config import Config
from claude_protect.diagnostics import diagnostic_report
from claude_protect.streaming import STREAM_PATH, assess, check


class TimedResponse:
    status = 200

    def __init__(self, clock, interval=2, body=b"**********"):
        self.clock = clock
        self.interval = interval
        self.body = io.BytesIO(body)

    def read(self, size):
        block = self.body.read(size)
        if block:
            self.clock[0] += self.interval
        return block


class StreamingTests(unittest.TestCase):
    def run_sample(self, interval=2, body=b"**********", reuse=True):
        clock = [0.0]
        with patch("claude_protect.cli.read_status", return_value={"session_isolated": True}), \
                patch("claude_protect.streaming.time.monotonic", side_effect=lambda: clock[0]), \
                patch("claude_protect.streaming.http.client.HTTPSConnection") as factory:
            connection = factory.return_value
            connection.sock = object()
            control = MagicMock(status=200)
            control.read.return_value = b"x"
            connection.getresponse.side_effect = [control, TimedResponse(clock, interval, body)]
            if not reuse:
                def request(method, path, **kwargs):
                    if path == STREAM_PATH:
                        connection.sock = object()
                connection.request.side_effect = request
            result = check(Config(uid=1000))
            connection.set_tunnel.assert_called_once_with("httpbin.org", 443)
            self.assertEqual(connection.request.call_count, 2)
            self.assertTrue(factory.call_args.kwargs["context"].check_hostname)
        return result

    def test_timed_stream_and_reuse_pass_without_claiming_claude_session_validation(self):
        result = self.run_sample()
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["connection_reused"])
        self.assertEqual(result["stream_span_ms"], 18000)
        self.assertEqual(result["body_bytes"], 10)
        self.assertEqual(result["claude_streaming"], "not_tested")
        self.assertEqual(result["account_safety"], "not_assessed")

    def test_buffered_body_is_inconclusive_and_truncated_body_fails(self):
        self.assertEqual(self.run_sample(interval=0)["status"], "inconclusive")
        self.assertEqual(self.run_sample(body=b"***")["status"], "failed")
        self.assertEqual(self.run_sample(body=b"xxxxxxxxxx")["status"], "failed")
        self.assertEqual(assess([0] * 10, b"*" * 10)[0], "inconclusive")

    def test_unobserved_connection_reuse_is_not_fabricated_as_success(self):
        result = self.run_sample(reuse=False)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["connection_reused"])

    def test_outside_isolation_and_mid_sample_policy_change_cannot_return_pass(self):
        with patch("claude_protect.cli.read_status", return_value={"session_isolated": False}), \
                patch("claude_protect.streaming.http.client.HTTPSConnection") as connection:
            with self.assertRaises(RuntimeError):
                check(Config(uid=1000))
            connection.assert_not_called()
        with patch("claude_protect.cli.read_status", side_effect=[{"session_isolated": True}, {"session_isolated": False}]), \
                patch("claude_protect.streaming.http.client.HTTPSConnection") as factory:
            factory.return_value.connect.side_effect = OSError()
            with self.assertRaises(RuntimeError):
                check(Config(uid=1000))

    def test_certificate_and_http_failures_are_transport_results_not_account_verdicts(self):
        with patch("claude_protect.cli.read_status", return_value={"session_isolated": True}), \
                patch("claude_protect.streaming.http.client.HTTPSConnection") as factory:
            connection = factory.return_value
            connection.connect.side_effect = ssl.SSLCertVerificationError("untrusted")
            result = check(Config(uid=1000))
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error"], "certificate_verification_failed")
            connection.request.assert_not_called()
        with patch("claude_protect.cli.read_status", return_value={"session_isolated": True}), \
                patch("claude_protect.streaming.http.client.HTTPSConnection") as factory:
            factory.return_value.getresponse.return_value.status = 429
            result = check(Config(uid=1000))
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["account_safety"], "not_assessed")

    def test_report_separates_generic_transport_from_real_claude_streaming(self):
        result = self.run_sample()
        result["raw_response"] = "never-export"
        report = diagnostic_report(streaming=result)
        self.assertEqual(report["streaming_transport"]["state"], "passed")
        self.assertEqual(report["streaming_transport"]["claude_streaming"], "not_tested")
        self.assertIn("claude_streaming_connection", report["not_tested"])
        self.assertNotIn("raw_response", report["streaming_transport"])


if __name__ == "__main__":
    unittest.main()
