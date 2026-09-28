#!/usr/bin/env python3
"""Exercise the frozen B40 update UI against a disposable same-signer B41 QA APK."""

import argparse
import hashlib
import http.server
import json
import re
import secrets
import subprocess
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


PACKAGE = "com.czenb.ujnb.transferb"
RUNNER = f"{PACKAGE}.test/androidx.test.runner.AndroidJUnitRunner"
B40_SHA = "9fbef0397928878f09e74d3cc58e55c2be87f3ca6575cc6767202b685b64e6fc"
B41_SHA = "6cf9c385faefe88b662767e330bf4571bdc1d04b85ba171b0908f63d6c4c827f"
TESTER_SHA = "a36ff77963bef8830fb355b07ee44e1427d5575ea2ec81779e3fe75bd70fb9ac"
B41_SIZE = 43090308
B41_NAME = "1.2.18-transfer.15-B-qa.db14-r2"
SYMBOLS_SHA = "01fe196e103ba4be3fb627a906614d707d82db6ab018bba7a29f5470242fba2b"
CERT_SHA = "119505119726637fa78168bfede71c366fa9a745a427063a84ae8ea06b3b241d"
WINDOW_XML = "/sdcard/qa-b40-upgrade-window.xml"
TUNNEL_HOST = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
PROGRESS = re.compile(r"已下载\s+(\d+)%")
SYMBOL = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")
POSTINSTALL_ERRORS = ("应用发生崩溃", "U酱 Crash Report", "无法确认最新版本")
PUBLIC_NOTICE_URL = ("https://206.187.208.47/announcements/transfer-official.json"
                     "?_ujnb_check=release_probe")


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(262144), b""):
            digest.update(chunk)
    return digest.hexdigest()


def retention_symbols(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 7 or any(not SYMBOL.fullmatch(value) for value in lines[:5]) or \
            any(not value.isdecimal() for value in lines[5:]):
        raise RuntimeError("B41 retention symbols must be the seven release-symbols.py lines")
    return {"cipherClass": lines[1], "decryptMethod": lines[3],
            "databaseClass": lines[4]}


def command(*args, timeout=45, check=True):
    result = subprocess.run(args, text=True, encoding="utf-8", errors="replace",
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({args[0]}): {result.stderr[-500:]}")
    return result.stdout


class Device:
    def __init__(self, serial):
        if not re.fullmatch(r"emulator-\d{4}", serial):
            raise ValueError("only an explicit isolated emulator is accepted")
        self.serial = serial

    def adb(self, *args, timeout=45):
        return command("adb", "-s", self.serial, *args, timeout=timeout)

    def require_isolated(self):
        if self.adb("shell", "getprop", "ro.kernel.qemu").strip() != "1":
            raise RuntimeError("QA device is not an emulator")
        if self.adb("get-serialno").strip() != self.serial:
            raise RuntimeError("ADB serial changed")
        return (self.adb("shell", "getprop", "ro.serialno").strip(),
                self.adb("shell", "getprop", "ro.build.fingerprint").strip())

    def installed(self):
        report = self.adb("shell", "dumpsys", "package", PACKAGE)
        def field(pattern):
            match = re.search(pattern, report)
            return match.group(1) if match else None
        identity = {"code": field(r"\bversionCode=(\d+)"),
                    "app_id": field(r"\bappId=(\d+)"),
                    "data_inode": field(r"\bceDataInode=(\d+)"),
                    "first_install": field(r"\bfirstInstallTime=([^\r\n]+)")}
        if any(value is None for value in identity.values()):
            raise RuntimeError("installed package identity is incomplete")
        return identity

    def installed_sha256(self):
        paths = self.adb("shell", "pm", "path", PACKAGE).splitlines()
        bases = [line.removeprefix("package:") for line in paths
                 if line.startswith("package:") and line.endswith("/base.apk")]
        if len(bases) != 1:
            raise RuntimeError("installed APK has no unique base.apk")
        output = self.adb("shell", "sha256sum", bases[0])
        match = re.match(r"([0-9a-f]{64})\s+", output)
        if not match:
            raise RuntimeError("installed APK digest is unavailable")
        return match.group(1)

    def instrument(self, test, arguments):
        params = ["shell", "am", "instrument", "-w", "-r", "-e", "class",
                  f"com.czenb.release.{test}"]
        for key, value in arguments.items():
            params.extend(("-e", key, str(value)))
        output = self.adb(*params, RUNNER, timeout=120)
        if "OK (1 test)" not in output or "FAILURES!!!" in output or "Process crashed" in output:
            raise RuntimeError(f"QA instrumentation {test} failed: {output[-700:]}")
        return output

    def policy(self, action, hardware, fingerprint, **extra):
        args = {"qaOperation": action, "qaAcknowledgement": "isolated-qa",
                "qaSerial": self.serial, "qaHardwareSerial": hardware,
                "qaFingerprint": fingerprint, **extra}
        return self.instrument(f"ReleasePolicyQaSeedTest#{action}", args)

    def window(self):
        failure = ""
        for attempt in range(3):
            try:
                self.adb("shell", "uiautomator", "dump", WINDOW_XML, timeout=25)
                raw = self.adb("exec-out", "cat", WINDOW_XML, timeout=15)
                if not raw.lstrip("\ufeff\r\n\t ").startswith("<"):
                    failure = f"non-XML bytes={len(raw)} prefix={raw[:8].encode().hex()}"
                else:
                    return [node.attrib for node in ET.fromstring(raw).iter("node")]
            except ET.ParseError as error:
                failure = f"malformed XML at {error.position}"
            except RuntimeError as error:
                failure = f"ADB dump failed: {error}"
            if attempt < 2:
                time.sleep(1)
        raise RuntimeError(f"UI hierarchy unavailable after 3 attempts: {failure}")

    def screenshot(self, path):
        result = subprocess.run(("adb", "-s", self.serial, "exec-out", "screencap", "-p"),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if result.returncode or not result.stdout.startswith(b"\x89PNG"):
            raise RuntimeError("QA screenshot failed")
        path.write_bytes(result.stdout)

    def tap(self, node):
        match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
        if not match:
            raise RuntimeError("visible QA control has no bounds")
        left, top, right, bottom = map(int, match.groups())
        if right <= left or bottom <= top:
            raise RuntimeError("visible QA control has invalid bounds")
        self.adb("shell", "input", "tap", str((left + right) // 2), str((top + bottom) // 2))

    def scroll_notice(self, nodes):
        title = next((node for node in nodes if node.get("package") == PACKAGE and
                      node.get("text") == "公告"), None)
        button = next((node for node in nodes if node.get("package") == PACKAGE and
                       node.get("text") == "下载新版本"), None)
        if title is None or button is None:
            return False
        title_bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", title.get("bounds", ""))
        button_bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", button.get("bounds", ""))
        if title_bounds is None or button_bounds is None:
            return False
        left, _, right, title_bottom = map(int, title_bounds.groups())
        button_top = int(button_bounds.group(2))
        gap = button_top - title_bottom
        if right <= left or gap < 160:
            return False
        x = (left + right) // 2
        self.adb("shell", "input", "swipe", str(x), str(title_bottom + 3 * gap // 4),
                 str(x), str(title_bottom + gap // 4), "350")
        return True


def status_field(output, name):
    values = re.findall(rf"(?m)^INSTRUMENTATION_STATUS: {re.escape(name)}=(.+)$", output)
    if len(values) != 1:
        raise RuntimeError(f"QA policy did not return one {name}")
    return values[0].strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise RuntimeError("QA APK URL redirected")


def public_notice_revision():
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(PUBLIC_NOTICE_URL, headers={
        "Accept": "application/vnd.github.raw+json", "User-Agent": "UJNB-Android",
        "Cache-Control": "no-cache"})
    with opener.open(request, timeout=15) as response:
        if response.status != 200 or response.geturl() != PUBLIC_NOTICE_URL:
            raise RuntimeError("public notice did not return the exact HTTPS URL")
        body = response.read(16385)
    if len(body) > 16384:
        raise RuntimeError("public notice exceeded the QA size limit")
    notice = json.loads(body)
    update = notice.get("requiredUpdate", {})
    if (notice.get("revision") != 25 or update.get("minimumVersionCode") != 39 or
            update.get("targetVersionCode") != 39):
        raise RuntimeError("public revision25 notice was not confirmed")
    return 25


def run(args):
    result = {"b40_sha256": B40_SHA, "b41_sha256": B41_SHA,
              "tester_sha256": TESTER_SHA, "qa_url_sha256": None, "progress_samples": [],
              "installer_seen": False, "data_retained": None,
              "marker_restored": False, "remote_revision_after_clear": None,
              "postinstall_home_seen": False, "retention_verified": False,
              "tunnel_stopped": False, "http_server_stopped": False, "status": "failed"}
    device = Device(args.serial)
    server = None
    thread = None
    tunnel = None
    tunnel_log = None
    marker_id = secrets.token_hex(16)
    seed_attempted = False
    isolated_verified = False
    hardware = fingerprint = None
    errors = []

    def restore_policy():
        inspect = device.policy("inspect", hardware, fingerprint)
        cache_sha = status_field(inspect, "qa_policy_cache_sha256")
        if status_field(inspect, "qa_policy_state") != "seeded" or \
                status_field(inspect, "qa_policy_id") != marker_id or \
                cache_sha != result["seed_cache_sha256"]:
            raise RuntimeError("QA marker or seeded payload changed; refusing to clear")
        cleared = device.policy("clear", hardware, fingerprint,
                                seedId=marker_id, seedPayloadSha256=cache_sha)
        if status_field(cleared, "qa_policy_state") != "restored" or \
                status_field(cleared, "qa_policy_id") != marker_id:
            raise RuntimeError("QA policy backup restoration receipt mismatch")
        result["marker_cleared"] = True
        # The instrumentation compares the restored cached payload byte-for-byte.
        result["marker_restored"] = True
        result["remote_revision_after_clear"] = public_notice_revision()
        if result["remote_revision_after_clear"] != result["remote_revision_before_seed"]:
            raise RuntimeError("public notice changed during isolated QA")

    try:
        if not re.fullmatch(r"[0-9a-f]{64}", B41_SHA) or B41_SIZE <= 0 or not B41_NAME:
            raise RuntimeError("compatible B41 QA artifact identity is not pinned")
        for path, expected in ((args.b40, B40_SHA), (args.tester, TESTER_SHA), (args.b41, B41_SHA)):
            if not path.is_file() or file_sha256(path) != expected:
                raise RuntimeError(f"frozen QA input mismatch: {path.name}")
        if args.b41.stat().st_size != B41_SIZE:
            raise RuntimeError("B41 QA size mismatch")
        result["symbols_sha256"] = file_sha256(args.symbols)
        if result["symbols_sha256"] != SYMBOLS_SHA:
            raise RuntimeError("B41 retention symbol mapping is not pinned to this APK")
        symbols = retention_symbols(args.symbols)
        hardware, fingerprint = device.require_isolated()
        isolated_verified = True
        device.adb("install", "--no-incremental", "-r", "-t", str(args.b40), timeout=120)
        device.adb("install", "--no-incremental", "-r", "-t", str(args.tester), timeout=120)
        before = device.installed()
        if before["code"] != "40" or device.installed_sha256() != B40_SHA:
            raise RuntimeError("isolated emulator did not install the frozen B40 bytes")
        result["before"] = before
        device.adb("shell", "appops", "set", PACKAGE, "REQUEST_INSTALL_PACKAGES", "allow")
        operation = device.adb("shell", "appops", "get", PACKAGE, "REQUEST_INSTALL_PACKAGES")
        if "allow" not in operation:
            raise RuntimeError("isolated unknown-source app-op was not enabled")

        device.instrument("UpgradeRetentionTest#seedOldVersion", {"oldVersionCode": "40"})
        result["retention_seeded"] = True
        result["remote_revision_before_seed"] = public_notice_revision()

        token = secrets.token_hex(24)
        route = f"/{token}/{args.b41.name}"
        apk = args.b41

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format_string, *values):
                pass

            def do_HEAD(self):
                self.serve(False)

            def do_GET(self):
                self.serve(True)

            def serve(self, body):
                if self.path != route:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.android.package-archive")
                self.send_header("Content-Length", str(B41_SIZE))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if body:
                    try:
                        with apk.open("rb") as source:
                            for chunk in iter(lambda: source.read(262144), b""):
                                self.wfile.write(chunk)
                                # Leave enough time for UI automation to observe an intermediate percentage.
                                time.sleep(0.08)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        tunnel_log = (args.workdir / "cloudflared.log").open("w+", encoding="utf-8")
        tunnel = subprocess.Popen((str(args.cloudflared), "tunnel", "--no-autoupdate",
                                   "--url", f"http://127.0.0.1:{server.server_port}"),
                                  stdout=tunnel_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 90
        public_host = None
        while time.monotonic() < deadline:
            tunnel_log.flush()
            log = (args.workdir / "cloudflared.log").read_text(encoding="utf-8", errors="replace")
            match = TUNNEL_HOST.search(log)
            if match:
                public_host = match.group(0)
                break
            if tunnel.poll() is not None:
                raise RuntimeError("ephemeral HTTPS tunnel ended before URL assignment")
            time.sleep(1)
        if not public_host:
            raise RuntimeError("ephemeral HTTPS tunnel did not become ready")
        url = public_host + route
        result["qa_url_sha256"] = hashlib.sha256(url.encode("utf-8")).hexdigest()
        print(f"qa_download_url_sha256={result['qa_url_sha256']}", flush=True)
        opener = urllib.request.build_opener(NoRedirect())
        deadline = time.monotonic() + 90
        while True:
            try:
                with opener.open(urllib.request.Request(url, method="HEAD"), timeout=15) as response:
                    if response.status != 200 or response.geturl() != url:
                        raise RuntimeError("QA HTTPS HEAD did not reach the exact file")
                break
            except Exception:
                if tunnel.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("QA HTTPS tunnel was unreachable")
                time.sleep(3)
        digest = hashlib.sha256()
        total = 0
        with opener.open(urllib.request.Request(url, headers={"Cache-Control": "no-cache"}),
                         timeout=60) as response:
            if response.status != 200 or response.geturl() != url:
                raise RuntimeError("QA HTTPS full GET did not reach the exact file")
            while chunk := response.read(262144):
                total += len(chunk)
                if total > B41_SIZE:
                    raise RuntimeError("QA HTTPS response exceeds B41 size")
                digest.update(chunk)
        if total != B41_SIZE or digest.hexdigest() != B41_SHA:
            raise RuntimeError("QA HTTPS full GET does not match B41 bytes")
        result["public_get_bytes"] = total
        print(f"qa_full_get_sha256={digest.hexdigest()} bytes={total}", flush=True)

        seed_attempted = True
        output = device.policy("seed", hardware, fingerprint, seedId=marker_id,
                               revision="26", targetVersionCode="41", versionName=B41_NAME,
                               downloadUrl=url, apkSha256=B41_SHA)
        if status_field(output, "qa_policy_state") != "seeded" or \
                status_field(output, "qa_policy_id") != marker_id:
            raise RuntimeError("QA policy seed receipt mismatch")
        result["seed_cache_sha256"] = status_field(output, "qa_policy_cache_sha256")
        device.adb("shell", "am", "force-stop", PACKAGE)
        device.adb("shell", "monkey", "-p", PACKAGE, "-c",
                   "android.intent.category.LAUNCHER", "1", timeout=30)
        deadline = time.monotonic() + 90
        last_nodes = []
        stable_home_samples = 0
        notice_scrolls = 0
        while time.monotonic() < deadline:
            nodes = device.window()
            last_nodes = nodes
            if any(node.get("text") == "开始使用" for node in nodes):
                device.tap(next(node for node in nodes if node.get("text") == "开始使用"))
            matches = [node for node in nodes if node.get("package") == PACKAGE and
                       node.get("text") == "下载新版本"]
            if matches and any(node.get("package") == PACKAGE and
                               node.get("text") == "请更新后继续使用" for node in nodes):
                device.screenshot(args.workdir / "b40-required.png")
                device.tap(matches[0])
                break
            if matches and notice_scrolls < 6 and device.scroll_notice(nodes):
                notice_scrolls += 1
            elif matches and notice_scrolls >= 6:
                break
            time.sleep(1)
        result["b40_notice_scrolls"] = notice_scrolls
        if not any(node.get("package") == PACKAGE and
                   node.get("text") == "请更新后继续使用" for node in last_nodes):
            device.screenshot(args.workdir / "b40-required-failure.png")
            known = ("开始使用", "请更新后继续使用", "下载新版本",
                     "无法获取最新状态，请检查网络后重试。", "设置", "我的")
            result["b40_visible_known_labels"] = sorted({node.get("text") for node in last_nodes
                                                         if node.get("text") in known})
            result["b40_process_running"] = bool(device.adb("shell", "pidof", PACKAGE).strip())
            raise RuntimeError("frozen B40 did not show the required-update marker")

        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            nodes = device.window()
            texts = [node.get("text", "") for node in nodes]
            for value in texts:
                match = PROGRESS.fullmatch(value)
                if match:
                    percent = int(match.group(1))
                    if percent not in result["progress_samples"]:
                        result["progress_samples"].append(percent)
                        if 0 < percent < 100 and not (args.workdir / "b40-progress.png").exists():
                            device.screenshot(args.workdir / "b40-progress.png")
            installer = next((node for node in nodes if node.get("text") in
                              ("Install", "Update", "安装", "更新") and
                              "packageinstaller" in node.get("package", "").lower()), None)
            if installer:
                result["installer_seen"] = True
                result["installer_package"] = installer.get("package")
                device.screenshot(args.workdir / "b41-installer.png")
                device.tap(installer)
                break
            if any("SHA-256 不匹配" in value or "发行证书不匹配" in value or
                   "下载或验证更新包失败" in value for value in texts):
                raise RuntimeError("B40 UI rejected the QA APK before the installer")
            time.sleep(1)
        else:
            raise RuntimeError("system installer did not open after the App download")
        if not any(0 < value < 100 for value in result["progress_samples"]):
            raise RuntimeError("application download percentage was not observed")
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            after = device.installed()
            if after["code"] == "41":
                break
            time.sleep(2)
        else:
            raise RuntimeError("system installer did not install code41")
        result["after"] = after
        result["installed_b41_sha256"] = device.installed_sha256()
        if result["installed_b41_sha256"] != B41_SHA:
            raise RuntimeError("installed base.apk is not the exact B41 QA artifact")
        result["data_retained"] = (before["app_id"] == after["app_id"] and
                                   before["data_inode"] == after["data_inode"] and
                                   before["first_install"] == after["first_install"])
        if not result["data_retained"]:
            raise RuntimeError("in-app install did not retain app identity and data directory")
        result["core_upgrade_passed"] = True
        restore_policy()
        device.adb("shell", "am", "force-stop", PACKAGE)
        device.adb("shell", "monkey", "-p", PACKAGE, "-c",
                   "android.intent.category.LAUNCHER", "1", timeout=30)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            nodes = device.window()
            texts = [node.get("text", "") for node in nodes]
            if any(error in value for value in texts for error in POSTINSTALL_ERRORS):
                device.screenshot(args.workdir / "b41-postinstall-failure.png")
                raise RuntimeError("B41 cold start showed CrashActivity or version-check failure")
            if any(node.get("text") in ("设置", "我的") and node.get("package") == PACKAGE
                   for node in nodes):
                stable_home_samples += 1
                if stable_home_samples >= 5:
                    result["postinstall_home_seen"] = True
                    device.screenshot(args.workdir / "b41-postinstall-home.png")
                    break
            else:
                stable_home_samples = 0
            if any(node.get("text") == "开始使用" for node in nodes):
                device.tap(next(node for node in nodes if node.get("text") == "开始使用"))
            if any(node.get("text") == "知道了" for node in nodes):
                device.tap(next(node for node in nodes if node.get("text") == "知道了"))
            time.sleep(1)
        else:
            device.screenshot(args.workdir / "b41-postinstall-failure.png")
            raise RuntimeError("B41 cold start did not reach the main screen")
        device.instrument("UpgradeRetentionTest#verifyNewVersion", symbols)
        result["retention_verified"] = True
        result["status"] = "complete_upgrade_passed"
        print("B40 in-app upgrade, B41 cold start, account and records: PASS", flush=True)
    except Exception as error:
        errors.append(str(error))
    finally:
        if seed_attempted and not result.get("marker_cleared") and hardware and fingerprint:
            try:
                restore_policy()
                device.adb("shell", "am", "force-stop", PACKAGE)
                device.adb("shell", "monkey", "-p", PACKAGE, "-c",
                           "android.intent.category.LAUNCHER", "1", timeout=30)
            except Exception as error:
                errors.append(f"QA policy cleanup/readback failed: {error}")
        if isolated_verified:
            try:
                device.adb("shell", "rm", "-f", WINDOW_XML)
            except Exception:
                pass
        if tunnel is not None:
            try:
                if tunnel.poll() is None:
                    tunnel.terminate()
                tunnel.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait(timeout=10)
            result["tunnel_stopped"] = tunnel.poll() is not None
        if tunnel_log is not None:
            tunnel_log.close()
        if server is not None:
            server.shutdown()
            server.server_close()
            if thread is not None:
                thread.join(timeout=10)
            result["http_server_stopped"] = thread is not None and not thread.is_alive()
        if errors:
            result["status"] = "failed"
            result["errors"] = errors
        args.workdir.joinpath("upgrade-result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({key: result[key] for key in
                          ("status", "progress_samples", "installer_seen", "data_retained",
                           "marker_cleared", "remote_revision_after_clear", "postinstall_home_seen",
                           "retention_verified",
                           "tunnel_stopped", "http_server_stopped") if key in result},
                         ensure_ascii=False), flush=True)
    return 1 if errors else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--b40", required=True, type=Path)
    parser.add_argument("--tester", required=True, type=Path)
    parser.add_argument("--b41", required=True, type=Path)
    parser.add_argument("--symbols", required=True, type=Path)
    parser.add_argument("--cloudflared", required=True, type=Path)
    parser.add_argument("--workdir", required=True, type=Path)
    arguments = parser.parse_args()
    raise SystemExit(run(arguments))
