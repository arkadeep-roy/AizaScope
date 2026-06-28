from __future__ import annotations

import unittest

from aizascope.classifier import advisory_for_classification
from aizascope.cvss import score_vector
from aizascope.input_loader import is_valid_aiza_key, load_single_key
from aizascope.models import HttpResult, ScanContext
from aizascope.probes import ProbeRunner

VALID_KEY = "AIza" + "A" * 35


class FakeHttpClient:
    def __init__(self):
        self.calls = []

    def _result(self, method: str, url: str, status: int, body: str = "{}") -> HttpResult:
        return HttpResult(method=method, url=url, status=status, headers={}, body_text=body, elapsed_ms=1)

    def request(self, method: str, url: str, *, headers=None, json_body=None, raw_body=None):
        self.calls.append({"method": method.upper(), "url": url, "headers": dict(headers or {}), "json_body": json_body, "raw_body": raw_body})

        if "getProjectConfig" in url:
            return self._result(method, url, 200, '{"projectId":"test-proj","databaseURL":"https://test-proj.firebaseio.com","storageBucket":"test-proj.appspot.com"}')

        if "accounts:signUp" in url:
            return self._result(method, url, 200, '{"idToken":"anon-token","localId":"local-1"}')

        if "accounts:delete" in url:
            return self._result(method, url, 200, '{}')

        if "firestore.googleapis.com" in url and "/documents/users" in url and method.upper() == "GET":
            if headers and headers.get("Authorization") == "Bearer anon-token":
                return self._result(method, url, 200, '{"documents":[{"name":"projects/test-proj/databases/(default)/documents/users/u1"}]}')
            return self._result(method, url, 403, '{"error":{"message":"PERMISSION_DENIED"}}')

        if "firestore.googleapis.com" in url and "/documents/aizascope_bbp_probe" in url and method.upper() == "POST":
            if headers and headers.get("Authorization") == "Bearer anon-token":
                return self._result(method, url, 200, '{"name":"projects/test-proj/databases/(default)/documents/aizascope_bbp_probe/proof"}')
            return self._result(method, url, 403, '{"error":{"message":"PERMISSION_DENIED"}}')

        if "firestore.googleapis.com/v1/projects/test-proj/databases/(default)/documents/aizascope_bbp_probe/proof" in url and method.upper() == "DELETE":
            if headers and headers.get("Authorization") == "Bearer anon-token":
                return self._result(method, url, 200, '{}')
            return self._result(method, url, 403, '{}')

        return self._result(method, url, 403, '{"error":{"message":"blocked"}}')


class CoreTests(unittest.TestCase):
    def test_aiza_validation(self):
        self.assertTrue(is_valid_aiza_key(VALID_KEY))
        self.assertEqual(load_single_key(VALID_KEY), ([VALID_KEY], []))
        self.assertFalse(is_valid_aiza_key("AIza-short"))

    def test_cvss_score(self):
        score, severity = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        self.assertEqual(score, 5.3)
        self.assertEqual(severity, "MEDIUM")

    def test_critical_review_advisory_not_swallowed_by_youtube_mapping(self):
        advisory = advisory_for_classification("YOUTUBE_OAUTH_ONLY_ENDPOINT_UNEXPECTED_SUCCESS_CRITICAL_REVIEW_REQUIRED")
        self.assertIn("Unexpected success", advisory["attack_class"])
        self.assertEqual(advisory["owasp_api_2023"], "API5:2023 Broken Function Level Authorization")

    def test_anon_auth_write_uses_token_before_cleanup(self):
        fake = FakeHttpClient()
        runner = ProbeRunner(fake)
        ctx = ScanContext(
            key=VALID_KEY,
            profile="aggressive-authorized",
            auth_mode="auto",
            write_proof="auto",
            non_interactive=True,
            store_full_key=False,
            timeout=1,
            user_agent="test",
            output_dir="/tmp/aizascope-test",
            youtube_expensive_proof="off",
            youtube_write_negative_control="off",
            gemini_token_proof="off",
            gemini_generation_proof="off",
            gemini_embed_proof="off",
            vision_proof="off",
            translation_proof="off",
            natural_language_proof="off",
        )
        findings = runner.run_all(ctx)
        classes = [f.classification for f in findings]
        self.assertIn("FIRESTORE_AUTH_LIST_CONFIRMED", classes)
        self.assertIn("FIRESTORE_AUTH_WRITE_PROOF_CONFIRMED", classes)
        self.assertIn("ANONYMOUS_AUTH_CLEANUP_ATTEMPTED", classes)

        write_calls = [c for c in fake.calls if c["method"] == "POST" and "/documents/aizascope_bbp_probe" in c["url"]]
        self.assertTrue(write_calls)
        self.assertEqual(write_calls[0]["headers"].get("Authorization"), "Bearer anon-token")

        cleanup_index = next(i for i, c in enumerate(fake.calls) if "accounts:delete" in c["url"])
        write_index = next(i for i, c in enumerate(fake.calls) if c["method"] == "POST" and "/documents/aizascope_bbp_probe" in c["url"])
        self.assertGreater(cleanup_index, write_index)


class FakeMapsRequestDeniedClient:
    def __init__(self):
        self.calls = []

    def _result(self, method: str, url: str, status: int, body: str = "{}", headers=None) -> HttpResult:
        return HttpResult(method=method, url=url, status=status, headers=headers or {"content-type": "application/json"}, body_text=body, elapsed_ms=1)

    def request(self, method: str, url: str, *, headers=None, json_body=None, raw_body=None):
        self.calls.append({"method": method.upper(), "url": url, "headers": dict(headers or {})})
        return self._result(method, url, 200, '{"status":"REQUEST_DENIED","error_message":"This API project is not authorized to use this API key."}')


class FakeGeminiModelClient:
    def __init__(self):
        self.calls = []

    def _result(self, method: str, url: str, status: int, body: str = "{}") -> HttpResult:
        return HttpResult(method=method, url=url, status=status, headers={"content-type": "application/json"}, body_text=body, elapsed_ms=1)

    def request(self, method: str, url: str, *, headers=None, json_body=None, raw_body=None):
        self.calls.append({"method": method.upper(), "url": url, "headers": dict(headers or {}), "json_body": json_body})
        if "models?" in url:
            return self._result(method, url, 200, '{"models":[{"name":"models/text-embedding-004","supportedGenerationMethods":["embedContent"]},{"name":"models/gemini-test-pro","supportedGenerationMethods":["generateContent","countTokens"]}]}')
        if ":countTokens" in url:
            return self._result(method, url, 200, '{"totalTokens":7}')
        if ":embedContent" in url:
            return self._result(method, url, 200, '{"embedding":{"values":[0.1,0.2]}}')
        return self._result(method, url, 403, '{"error":{"message":"blocked"}}')


class StressFixTests(unittest.TestCase):
    def test_maps_request_denied_http_200_is_not_allowed(self):
        runner = ProbeRunner(FakeMapsRequestDeniedClient())
        ctx = ScanContext(
            key=VALID_KEY, profile="standard", auth_mode="off", write_proof="off", non_interactive=True,
            store_full_key=False, timeout=1, user_agent="test", output_dir="/tmp/aizascope-test"
        )
        findings = runner.maps(ctx)
        classes = [f.classification for f in findings]
        self.assertTrue(classes)
        self.assertTrue(all("ALLOWED" not in c for c in classes))
        self.assertTrue(any("REQUEST_DENIED_OR_RESTRICTED" in c for c in classes))

    def test_gemini_active_proofs_choose_supported_models(self):
        fake = FakeGeminiModelClient()
        runner = ProbeRunner(fake)
        ctx = ScanContext(
            key=VALID_KEY, profile="active", auth_mode="off", write_proof="off", non_interactive=True,
            store_full_key=False, timeout=1, user_agent="test", output_dir="/tmp/aizascope-test",
            gemini_token_proof="auto", gemini_embed_proof="auto", gemini_generation_proof="off",
            vision_proof="off", translation_proof="off", natural_language_proof="off"
        )
        findings = runner.gemini(ctx)
        token_calls = [c for c in fake.calls if ":countTokens" in c["url"]]
        embed_calls = [c for c in fake.calls if ":embedContent" in c["url"]]
        self.assertTrue(token_calls)
        self.assertIn("gemini-test-pro:countTokens", token_calls[0]["url"])
        self.assertTrue(embed_calls)
        self.assertIn("text-embedding-004:embedContent", embed_calls[0]["url"])
        classes = [f.classification for f in findings]
        self.assertIn("GEMINI_COUNT_TOKENS_CONFIRMED", classes)
        self.assertIn("GEMINI_EMBED_CONTENT_CONFIRMED", classes)


class UXPolicyTests(unittest.TestCase):
    def test_default_command_is_full_no_prompt_scan(self):
        from aizascope.cli import apply_execution_policy, build_parser
        parser = build_parser()
        args = parser.parse_args(["keys.txt"])
        apply_execution_policy(args)
        self.assertEqual(args.mode, "full")
        self.assertEqual(args.profile, "aggressive-authorized")
        self.assertEqual(args.auth_mode, "auto")
        self.assertEqual(args.write_proof, "off")
        self.assertEqual(args.youtube_expensive_proof, "auto")
        self.assertEqual(args.gemini_token_proof, "auto")
        self.assertEqual(args.gemini_generation_proof, "auto")
        self.assertEqual(args.vision_proof, "auto")
        self.assertEqual(args.safe_browsing_proof, "auto")
        self.assertTrue(args.non_interactive)
        self.assertEqual(args.prompt_policy, "never")

    def test_prove_write_explicitly_enables_marker_writes(self):
        from aizascope.cli import apply_execution_policy, build_parser
        parser = build_parser()
        args = parser.parse_args(["keys.txt", "--prove-write"])
        apply_execution_policy(args)
        self.assertEqual(args.mode, "full")
        self.assertEqual(args.profile, "aggressive-authorized")
        self.assertEqual(args.write_proof, "auto")
        self.assertTrue(args.non_interactive)

    def test_quick_alias_is_short_and_non_interactive(self):
        from aizascope.cli import apply_execution_policy, build_parser
        parser = build_parser()
        args = parser.parse_args(["keys.txt", "--quick"])
        apply_execution_policy(args)
        self.assertEqual(args.mode, "quick")
        self.assertEqual(args.profile, "active")
        self.assertEqual(args.write_proof, "off")
        self.assertEqual(args.youtube_expensive_proof, "off")
        self.assertEqual(args.gemini_token_proof, "auto")
        self.assertEqual(args.safe_browsing_proof, "auto")
        self.assertTrue(args.non_interactive)

    def test_prompt_policy_once_reuses_decision_across_dynamic_prompts(self):
        import builtins
        runner = ProbeRunner(FakeHttpClient())
        ctx = ScanContext(
            key=VALID_KEY, profile="active", auth_mode="ask", write_proof="off", non_interactive=False,
            store_full_key=False, timeout=1, user_agent="test", output_dir="/tmp/aizascope-test",
            prompt_policy="once", prompt_decisions={},
        )
        calls = []
        old_input = builtins.input
        try:
            builtins.input = lambda prompt: calls.append(prompt) or "y"
            self.assertTrue(runner._confirm(ctx, "Create temporary anonymous Firebase Auth user for project p1? [y/N] "))
            self.assertTrue(runner._confirm(ctx, "Create temporary anonymous Firebase Auth user for project p2? [y/N] "))
        finally:
            builtins.input = old_input
        self.assertEqual(len(calls), 1)
        self.assertEqual(ctx.prompt_decisions.get("firebase.anonymousAuth"), True)

class GitHubPublicationUXTests(unittest.TestCase):
    def test_key_equals_syntax_loads_single_key(self):
        from aizascope.cli import build_parser, load_inputs
        parser = build_parser()
        args = parser.parse_args([f"--key={VALID_KEY}"])
        keys, invalid = load_inputs(args)
        self.assertEqual(keys, [VALID_KEY])
        self.assertEqual(invalid, [])

    def test_show_probe_wordlists_exits_cleanly(self):
        import contextlib
        import io
        from aizascope.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["--show-probe-wordlists"]), 0)
        self.assertIn("probe candidates", buf.getvalue())

    def test_positional_single_key_still_works(self):
        from aizascope.cli import build_parser, load_inputs
        parser = build_parser()
        args = parser.parse_args([VALID_KEY])
        keys, invalid = load_inputs(args)
        self.assertEqual(keys, [VALID_KEY])
        self.assertEqual(invalid, [])

    def test_file_equals_syntax_parses(self):
        from aizascope.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["--file=keys.txt"])
        self.assertEqual(args.file, "keys.txt")

    def test_branding_and_version_are_available(self):
        from aizascope.models import VERSION, AUTHOR, TOOL_NAME
        self.assertEqual(TOOL_NAME, "AizaScope")
        self.assertEqual(AUTHOR, "ARoy")
        self.assertIsInstance(VERSION, str)
        self.assertTrue(VERSION)

class OutputPolicyTests(unittest.TestCase):
    def test_ready_commands_json_embeds_key_and_filters_blocked(self):
        import json
        import tempfile
        from pathlib import Path
        from aizascope.reporter import write_ready_commands_json_records, write_curl_pocs_records
        from aizascope.models import sha256_text

        key = VALID_KEY
        records = [
            {
                "api_key": "AIzaAAAA...AAAA",
                "api_key_sha256": sha256_text(key),
                "suggested_priority": "MEDIUM",
                "classification": "MAPS_JAVASCRIPT_API_ALLOWED_FROM_ARBITRARY_CLIENT",
                "service": "maps.googleapis.com",
                "method_name": "mapsjs.loader",
                "http_status": 200,
                "details": {},
            },
            {
                "api_key": "AIzaAAAA...AAAA",
                "api_key_sha256": sha256_text(key),
                "suggested_priority": "INFO",
                "classification": "YOUTUBE_DATA_API_RESTRICTED_OR_BLOCKED",
                "service": "youtube.googleapis.com",
                "method_name": "videos.list",
                "http_status": 403,
                "details": {},
            },
        ]
        with tempfile.TemporaryDirectory() as td:
            json_path = write_ready_commands_json_records(records, td, {sha256_text(key): key})
            data = json.loads(Path(json_path).read_text())
            self.assertEqual(data["count"], 1)
            self.assertEqual(data["commands"][0]["api_key"], key)
            self.assertIn(key, data["commands"][0]["commands"][0])
            self.assertNotIn("RESTRICTED_OR_BLOCKED", json.dumps(data))

            sh_path = write_curl_pocs_records(records, td, {sha256_text(key): key})
            shell = Path(sh_path).read_text()
            self.assertIn(key, shell)
            self.assertIn("MAPS_JAVASCRIPT_API_ALLOWED", shell)
            self.assertNotIn("YOUTUBE_DATA_API_RESTRICTED_OR_BLOCKED", shell)


    def test_allowed_empty_is_not_actionable(self):
        from aizascope.reporter import is_actionable_record
        record = {
            "suggested_priority": "MEDIUM",
            "classification": "GEMINI_FILES_API_ALLOWED_EMPTY",
            "service": "generativelanguage.googleapis.com",
            "method_name": "files.list",
        }
        self.assertFalse(is_actionable_record(record, min_priority="MEDIUM"))

    def test_confirmed_finding_is_actionable(self):
        from aizascope.reporter import is_actionable_record
        record = {
            "suggested_priority": "HIGH",
            "classification": "FIRESTORE_UNAUTH_LIST_CONFIRMED",
            "service": "firestore.googleapis.com",
            "method_name": "documents.list.unauth",
        }
        self.assertTrue(is_actionable_record(record, min_priority="MEDIUM"))

    def test_console_summary_hides_info_counts(self):
        import io
        import contextlib
        from aizascope.cli import build_parser, print_console_summary
        parser = build_parser()
        args = parser.parse_args(["keys.txt"])
        records = [
            {"suggested_priority": "MEDIUM", "classification": "MAPS_JAVASCRIPT_API_ALLOWED_FROM_ARBITRARY_CLIENT", "service": "s", "method_name": "m", "api_key": "AIzaAAAA...AAAA"},
            {"suggested_priority": "INFO", "classification": "NOISE", "service": "s", "method_name": "m", "api_key": "AIzaAAAA...AAAA"},
        ]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_console_summary(records, args)
        out = buf.getvalue()
        self.assertIn("MEDIUM: 1", out)
        self.assertNotIn("INFO:", out)
        self.assertIn("Detailed raw records saved: 2", out)

class SingleKeyTerminalPoCTests(unittest.TestCase):
    def test_single_key_terminal_poc_commands_embed_key(self):
        from argparse import Namespace
        from io import StringIO
        from contextlib import redirect_stdout
        from aizascope.cli import print_single_key_poc_commands

        record = {
            "suggested_priority": "MEDIUM",
            "classification": "MAPS_JAVASCRIPT_API_ALLOWED_FROM_ARBITRARY_CLIENT",
            "service": "maps.googleapis.com",
            "method_name": "mapsjs.loader",
            "api_key_sha256": "sha256:test",
            "http_status": 200,
            "details": {},
        }
        args = Namespace(silent=False, jsonl_stdout=False)
        buf = StringIO()
        with redirect_stdout(buf):
            print_single_key_poc_commands([record], VALID_KEY, args)
        out = buf.getvalue()
        self.assertIn("Ready-to-run PoC commands", out)
        self.assertIn(VALID_KEY, out)
        self.assertIn("curl -s", out)

    def test_single_key_terminal_poc_commands_skip_info(self):
        from argparse import Namespace
        from io import StringIO
        from contextlib import redirect_stdout
        from aizascope.cli import print_single_key_poc_commands

        record = {
            "suggested_priority": "INFO",
            "classification": "FIREBASE_PROJECT_RESOLVED",
            "service": "identitytoolkit.googleapis.com",
            "method_name": "getProjectConfig",
            "api_key_sha256": "sha256:test",
            "http_status": 200,
            "details": {},
        }
        args = Namespace(silent=False, jsonl_stdout=False)
        buf = StringIO()
        with redirect_stdout(buf):
            print_single_key_poc_commands([record], VALID_KEY, args)
        out = buf.getvalue()
        self.assertIn("No MEDIUM+", out)
        self.assertNotIn(VALID_KEY, out)


class SeverityDisciplineTests(unittest.TestCase):
    def test_gemini_empty_lists_are_low_not_medium(self):
        class FakeEmptyGeminiClient:
            def request(self, method, url, *, headers=None, json_body=None, raw_body=None):
                if "models?" in url:
                    return HttpResult(method=method, url=url, status=200, headers={"content-type":"application/json"}, body_text='{"models":[]}', elapsed_ms=1)
                if "files" in url:
                    return HttpResult(method=method, url=url, status=200, headers={"content-type":"application/json"}, body_text='{"files":[]}', elapsed_ms=1)
                if "cachedContents" in url:
                    return HttpResult(method=method, url=url, status=200, headers={"content-type":"application/json"}, body_text='{"cachedContents":[]}', elapsed_ms=1)
                if "batches" in url:
                    return HttpResult(method=method, url=url, status=200, headers={"content-type":"application/json"}, body_text='{"batches":[]}', elapsed_ms=1)
                return HttpResult(method=method, url=url, status=403, headers={}, body_text='{}', elapsed_ms=1)
        runner = ProbeRunner(FakeEmptyGeminiClient())
        ctx = ScanContext(
            key=VALID_KEY, profile="standard", auth_mode="off", write_proof="off", non_interactive=True,
            store_full_key=False, timeout=1, user_agent="test", output_dir="/tmp/aizascope-test",
            gemini_token_proof="off", gemini_generation_proof="off", gemini_embed_proof="off"
        )
        findings = runner.gemini(ctx)
        priority_by_class = {f.classification: f.suggested_priority for f in findings}
        self.assertEqual(priority_by_class.get("GEMINI_FILES_API_ALLOWED_EMPTY"), "LOW")
        self.assertEqual(priority_by_class.get("GEMINI_CACHED_CONTENT_API_ALLOWED_EMPTY"), "LOW")
        self.assertEqual(priority_by_class.get("GEMINI_BATCH_API_ALLOWED_EMPTY"), "LOW")

    def test_safe_browsing_callable_is_low_not_actionable(self):
        class FakeSafeBrowsingClient:
            def request(self, method, url, *, headers=None, json_body=None, raw_body=None):
                return HttpResult(method=method, url=url, status=200, headers={"content-type":"application/json"}, body_text='{}', elapsed_ms=1)
        runner = ProbeRunner(FakeSafeBrowsingClient())
        ctx = ScanContext(
            key=VALID_KEY, profile="active", auth_mode="off", write_proof="off", non_interactive=True,
            store_full_key=False, timeout=1, user_agent="test", output_dir="/tmp/aizascope-test",
            safe_browsing_proof="auto"
        )
        findings = runner.safe_browsing(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].suggested_priority, "LOW")
        self.assertIn("SAFE_BROWSING_API_CALLABLE", findings[0].classification)

    def test_attack_chain_does_not_mark_partial_firebase_as_critical(self):
        from aizascope.chain_builder import build_attack_chains
        from aizascope.models import sha256_text
        record = {
            "api_key":"AIzaAAAA...AAAA",
            "api_key_sha256":sha256_text(VALID_KEY),
            "suggested_priority":"MEDIUM",
            "classification":"FIRESTORE_COLLECTION_IDS_EXPOSED",
            "service":"firestore.googleapis.com",
            "method_name":"documents.listCollectionIds",
            "evidence_level":"E4",
        }
        chains = build_attack_chains([record])
        self.assertTrue(chains)
        self.assertTrue(all(c["severity"] != "CRITICAL" for c in chains))


if __name__ == "__main__":
    unittest.main()
