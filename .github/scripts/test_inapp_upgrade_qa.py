#!/usr/bin/env python3
"""Local orchestration checks; no ADB device or public tunnel is used."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("inapp_upgrade_qa.py")
SPEC = importlib.util.spec_from_file_location("inapp_upgrade_qa", SCRIPT)
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)


class FakeDevice:
    def __init__(self, retain_data=True, failure=None):
        self.retain_data = retain_data
        self.failure = failure
        self.code = "40"
        self.screen = 0
        self.policies = []
        self.marker = None
        self.seeded_sha = "a" * 64
        self.retention_seeded = False
        self.retention_verified = False

    def require_isolated(self):
        return "EMU1234", "qa/build/fingerprint"

    def adb(self, *args, **kwargs):
        if args[:4] == ("shell", "appops", "get", qa.PACKAGE):
            return "REQUEST_INSTALL_PACKAGES: allow"
        return "Success"

    def installed(self):
        unchanged = self.code == "40" or self.retain_data
        return {"code": self.code, "app_id": "10123" if unchanged else "10124",
                "data_inode": "216727" if unchanged else "216728",
                "first_install": "original" if unchanged else "changed"}

    def installed_sha256(self):
        return qa.B40_SHA if self.code == "40" else qa.B41_SHA

    def policy(self, operation, hardware, fingerprint, **extra):
        self.policies.append(operation)
        if operation == "seed":
            self.marker = extra["seedId"]
            state = "seeded"
        elif operation == "inspect":
            state = "seeded"
            if self.failure == "marker_changed":
                return ("INSTRUMENTATION_STATUS: qa_policy_state=seeded\n"
                        "INSTRUMENTATION_STATUS: qa_policy_id=other\n"
                        f"INSTRUMENTATION_STATUS: qa_policy_cache_sha256={self.seeded_sha}\n"
                        "OK (1 test)\n")
        else:
            assert operation == "clear" and extra["seedId"] == self.marker
            assert extra["seedPayloadSha256"] == self.seeded_sha
            self.marker = None
            state = "restored"
        return (f"INSTRUMENTATION_STATUS: qa_policy_state={state}\n"
                f"INSTRUMENTATION_STATUS: qa_policy_id={extra.get('seedId', self.marker)}\n"
                f"INSTRUMENTATION_STATUS: qa_policy_cache_sha256={self.seeded_sha}\n"
                "OK (1 test)\n")

    def instrument(self, test, arguments):
        if test == "UpgradeRetentionTest#seedOldVersion":
            assert self.code == "40" and arguments == {"oldVersionCode": "40"}
            self.retention_seeded = True
            return "OK (1 test)\n"
        if test == "UpgradeRetentionTest#verifyNewVersion":
            assert self.code == "41" and self.marker is None
            assert arguments == {"cipherClass": "a.b", "decryptMethod": "d",
                                 "databaseClass": "c.e"}
            if self.failure == "retention":
                raise RuntimeError("fixture bookmark was lost")
            self.retention_verified = True
            return "OK (1 test)\n"
        assert test == "ReleaseNoticeProbeTest#readOnlyNoticeRevisions"
        cached = "26" if self.marker else "25"
        if self.failure == "backup" and self.policies and self.policies[-1] == "clear":
            cached = "null"
        return f"notice_probe bundled=25 cached={cached} remote=25 http=200 bytes=1\nOK (1 test)"

    def window(self):
        if self.code == "41" and self.marker is None:
            if self.failure == "crash":
                return [self.node("应用发生崩溃")]
            if self.failure == "version_check":
                return [self.node("无法确认最新版本，请联网后重新检查。")]
            return [self.node("设置"), self.node("我的")]
        self.screen += 1
        if self.screen == 1:
            return [self.node("请更新后继续使用"), self.node("下载新版本")]
        if self.screen == 2:
            return [self.node("已下载 32%")]
        return [self.node("Install", "com.google.android.packageinstaller")]

    @staticmethod
    def node(label, package=qa.PACKAGE):
        return {"text": label, "package": package, "bounds": "[1,1][100,100]"}

    def tap(self, node):
        if node["text"] == "Install":
            self.code = "41"

    def screenshot(self, path):
        path.write_bytes(b"\x89PNG\r\n\x1a\nfixture")


class FakeTunnel:
    def __init__(self, args, **kwargs):
        self.port = int(args[-1].rsplit(":", 1)[1])
        self.exit_code = None
        kwargs["stdout"].write("https://isolated.trycloudflare.com\n")
        kwargs["stdout"].flush()

    def poll(self):
        return self.exit_code

    def terminate(self):
        self.exit_code = 0

    def kill(self):
        self.exit_code = -9

    def wait(self, timeout=None):
        return self.exit_code


class LocalResponse:
    def __init__(self, response, requested_url):
        self.response = response
        self.requested_url = requested_url
        self.status = response.status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.response.close()

    def read(self, size):
        return self.response.read(size)

    def geturl(self):
        return self.requested_url


class UpgradeScriptTest(unittest.TestCase):
    def run_scenario(self, retain_data=True, failure=None):
        original_opener = urllib.request.build_opener
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = [root / name for name in ("b40.apk", "runner.apk", "b41.apk", "symbols.txt")]
            for path, content in zip(files, (b"old", b"tester", b"new" * 128,
                                            b"bridge\na.b\ne\nd\nc.e\n1\n2\n")):
                path.write_bytes(content)
            digests = [hashlib.sha256(path.read_bytes()).hexdigest() for path in files]
            device = FakeDevice(retain_data, failure)
            active_tunnel = None

            def create_tunnel(args, **kwargs):
                nonlocal active_tunnel
                active_tunnel = FakeTunnel(args, **kwargs)
                return active_tunnel

            class LocalOpener:
                def open(self, request, timeout=None):
                    target = f"http://127.0.0.1:{active_tunnel.port}{request.full_url.split('.com', 1)[1]}"
                    local = urllib.request.Request(target, method=request.get_method())
                    return LocalResponse(original_opener().open(local, timeout=timeout),
                                         request.full_url)

            args = SimpleNamespace(serial="emulator-5558", b40=files[0], tester=files[1],
                                   b41=files[2], symbols=files[3],
                                   cloudflared=root / "cloudflared", workdir=root)
            with patch.object(qa, "B40_SHA", digests[0]), \
                 patch.object(qa, "TESTER_SHA", digests[1]), \
                 patch.object(qa, "B41_SHA", digests[2]), \
                 patch.object(qa, "B41_SIZE", files[2].stat().st_size), \
                 patch.object(qa, "B41_NAME", "compatible-qa-test"), \
                 patch.object(qa, "SYMBOLS_SHA", digests[3]), \
                 patch.object(qa, "Device", return_value=device), \
                 patch.object(qa.subprocess, "Popen", side_effect=create_tunnel), \
                 patch.object(qa.urllib.request, "build_opener", return_value=LocalOpener()), \
                 patch.object(qa.time, "sleep", return_value=None):
                exit_code = qa.run(args)
            result = json.loads((root / "upgrade-result.json").read_text(encoding="utf-8"))
            self.assertTrue(device.retention_seeded)
            if failure == "marker_changed":
                self.assertEqual(["seed", "inspect", "inspect"], device.policies)
                self.assertIsNotNone(device.marker)
            else:
                self.assertEqual(["seed", "inspect", "clear"], device.policies)
                self.assertIsNone(device.marker)
            self.assertTrue(result["tunnel_stopped"])
            self.assertTrue(result["http_server_stopped"])
            self.assertEqual([32], result["progress_samples"])
            self.assertEqual(len(files[2].read_bytes()), result["public_get_bytes"])
            self.assertNotIn("qa_url", result)
            self.assertEqual(64, len(result["qa_url_sha256"]))
            self.assertEqual(digests[3], result["symbols_sha256"])
            self.assertEqual(device.retention_verified, result["retention_verified"])
            return exit_code, result

    def test_successful_upgrade(self):
        exit_code, result = self.run_scenario()
        self.assertEqual(0, exit_code)
        self.assertEqual("complete_upgrade_passed", result["status"])
        self.assertTrue(result["data_retained"])
        self.assertTrue(result["postinstall_home_seen"])
        self.assertTrue(result["retention_verified"])
        self.assertTrue(result["marker_restored"])
        self.assertEqual(25, result["remote_revision_after_clear"])

    def test_data_loss_fails_and_cleans_up(self):
        exit_code, result = self.run_scenario(False)
        self.assertEqual(1, exit_code)
        self.assertEqual("failed", result["status"])
        self.assertFalse(result["data_retained"])
        self.assertIn("did not retain", result["errors"][0])

    def test_installed_identity_uses_app_id_and_data_inode(self):
        report = ("appId=10492\nversionCode=41 minSdk=23\n"
                  "User 0: ceDataInode=216727 installed=true\n"
                  "firstInstallTime=2026-09-27 18:37:25\n"
                  "userId=0\n")
        device = qa.Device("emulator-5558")
        with patch.object(device, "adb", return_value=report):
            self.assertEqual({"code": "41", "app_id": "10492", "data_inode": "216727",
                              "first_install": "2026-09-27 18:37:25"}, device.installed())
        with patch.object(device, "adb", return_value=report.replace("ceDataInode=216727", "")):
            with self.assertRaisesRegex(RuntimeError, "identity is incomplete"):
                device.installed()

    def test_crash_screen_fails_after_policy_cleanup(self):
        exit_code, result = self.run_scenario(failure="crash")
        self.assertEqual(1, exit_code)
        self.assertFalse(result["postinstall_home_seen"])
        self.assertTrue(result["marker_restored"])
        self.assertIn("CrashActivity", result["errors"][0])

    def test_version_check_failure_is_not_a_successful_upgrade(self):
        exit_code, result = self.run_scenario(failure="version_check")
        self.assertEqual(1, exit_code)
        self.assertFalse(result["retention_verified"])
        self.assertIn("version-check failure", result["errors"][0])

    def test_policy_backup_readback_mismatch_fails(self):
        exit_code, result = self.run_scenario(failure="backup")
        self.assertEqual(1, exit_code)
        self.assertFalse(result["marker_restored"])
        self.assertIn("backup revision", result["errors"][0])

    def test_different_marker_is_never_cleared(self):
        exit_code, result = self.run_scenario(failure="marker_changed")
        self.assertEqual(1, exit_code)
        self.assertFalse(result.get("marker_cleared", False))
        self.assertIn("marker or seeded payload changed", result["errors"][0])

    def test_lost_account_or_record_fails(self):
        exit_code, result = self.run_scenario(failure="retention")
        self.assertEqual(1, exit_code)
        self.assertTrue(result["postinstall_home_seen"])
        self.assertFalse(result["retention_verified"])
        self.assertIn("bookmark was lost", result["errors"][0])

    def test_invalid_release_symbols_fail_before_device_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            symbols = root / "symbols.txt"
            symbols.write_text("a\nb\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "seven release-symbols.py lines"):
                qa.retention_symbols(symbols)

    def test_unpinned_compatible_apk_does_not_contact_device(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(serial="emulator-5558", b40=root / "old.apk",
                                   tester=root / "tester.apk", b41=root / "new.apk",
                                   symbols=root / "symbols.txt", workdir=root,
                                   cloudflared=root / "cloudflared")
            with patch.object(qa, "B41_SHA", ""), patch.object(qa, "Device") as device:
                self.assertEqual(1, qa.run(args))
                device.return_value.require_isolated.assert_not_called()
                device.return_value.adb.assert_not_called()
            result = json.loads((root / "upgrade-result.json").read_text(encoding="utf-8"))
            self.assertIn("not pinned", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
