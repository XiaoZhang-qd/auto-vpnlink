#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import http.cookies
import json
import os
import secrets
import subprocess
import sys
import threading
import time

from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo, available_timezones


# ============================================================
# 基础配置
# ============================================================

ROOT = Path(__file__).resolve().parent

CONFIG_FILE = ROOT / ".auto_vpnlink_config.json"

HOST = os.getenv("AUTO_VPN_HOST", "0.0.0.0")
PORT = int(os.getenv("AUTO_VPN_PORT", "8080"))

DEFAULT_TIME = "11:30"
DEFAULT_TZ = "Asia/Shanghai"


# ============================================================
# 五个与 GitHub Actions 对应的参数
# ============================================================

DEFAULT_PARAMETERS = {
    "search_limit": 5000,
    "health_candidate_limit": 300,
    "health_success_target": 20,
    "cfw_candidate_limit": 150,
    "cfw_success_target": 10,
}

PARAMETER_RANGES = {
    "search_limit": (1, 20000),
    "health_candidate_limit": (1, 5000),
    "health_success_target": (1, 5000),
    "cfw_candidate_limit": (1, 2000),
    "cfw_success_target": (1, 2000),
}


# ============================================================
# 运行状态
# ============================================================

LOCK = threading.Lock()
CFG_LOCK = threading.RLock()

SESSIONS = set()

STATE = {
    "running": False,
    "last_start": None,
    "last_finish": None,
    "last_ok": None,
    "last_error": None,
    "last_output": "",
}


# ============================================================
# 时间 / 时区
# ============================================================

def parse_time(value):
    try:
        h, m = map(int, str(value).split(":", 1))
    except Exception as exc:
        raise ValueError("时间必须使用 HH:MM 格式") from exc

    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError("时间必须在 00:00 到 23:59 之间")

    return h, m


def valid_tz(value):
    try:
        ZoneInfo(str(value))
    except Exception as exc:
        raise ValueError("无效的 IANA 时区") from exc

    return str(value)


# ============================================================
# 密码
# ============================================================

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        310000,
    )

    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, digest_hex):
    try:
        salt = bytes.fromhex(salt_hex)

        _, digest = hash_password(password, salt)

        return hmac.compare_digest(digest, digest_hex)

    except Exception:
        return False


def random_password(length=20):
    chars = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "abcdefghijkmnopqrstuvwxyz"
        "23456789-_"
    )

    return "".join(
        secrets.choice(chars)
        for _ in range(length)
    )


# ============================================================
# 配置文件
# ============================================================

def save_config(config):
    temp_file = CONFIG_FILE.with_suffix(".tmp")

    temp_file.write_text(
        json.dumps(
            config,
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    os.replace(temp_file, CONFIG_FILE)


def validate_parameters(data):
    result = {}

    for key, (minimum, maximum) in PARAMETER_RANGES.items():

        try:
            value = int(data[key])
        except Exception as exc:
            raise ValueError(
                f"{key} 必须是整数"
            ) from exc

        if not minimum <= value <= maximum:
            raise ValueError(
                f"{key} 必须在 {minimum} 到 {maximum} 之间"
            )

        result[key] = value

    return result


def load_config():

    if CONFIG_FILE.exists():

        try:

            config = json.loads(
                CONFIG_FILE.read_text(
                    encoding="utf-8"
                )
            )

            schedule_time = config.get(
                "schedule_time",
                DEFAULT_TIME,
            )

            timezone = config.get(
                "timezone",
                DEFAULT_TZ,
            )

            parse_time(schedule_time)
            valid_tz(timezone)

            for key, default in DEFAULT_PARAMETERS.items():

                if key not in config:
                    config[key] = default

            validate_parameters(config)

            if (
                config.get("password_salt")
                and config.get("password_hash")
            ):
                save_config(config)

                return config

        except Exception:

            print(
                "[config] 配置无效，将重新初始化。",
                flush=True,
            )

    # --------------------------------------------------------
    # 首次运行
    # --------------------------------------------------------

    password = (
        os.getenv("AUTO_VPN_ADMIN_PASSWORD")
        or random_password()
    )

    salt, digest = hash_password(password)

    config = {
        "schedule_time": DEFAULT_TIME,
        "timezone": DEFAULT_TZ,

        **DEFAULT_PARAMETERS,

        "password_salt": salt,
        "password_hash": digest,

        "created_at": (
            datetime.now()
            .astimezone()
            .isoformat()
        ),
    }

    save_config(config)

    print("=" * 70)
    print("auto-vpnlink 首次运行")
    print()
    print("管理员密码：")
    print(password)
    print()
    print("⚠️ 这个密码只会在首次初始化时显示。")
    print("请立即保存。")
    print()
    print(
        f"管理员面板：http://127.0.0.1:{PORT}/admin"
    )
    print("=" * 70)

    return config


CFG = load_config()


def get_config():
    with CFG_LOCK:
        return dict(CFG)


def update_config(**values):

    global CFG

    with CFG_LOCK:

        CFG = {
            **CFG,
            **values,
        }

        save_config(CFG)

        return dict(CFG)


# ============================================================
# 将五个参数传给本地任务
# ============================================================

def build_pipeline_environment(config):

    env = os.environ.copy()

    # 搜索数量
    env["SEARCH_LIMIT"] = str(
        config["search_limit"]
    )

    env["MAX_DISCOVERED_NODES"] = str(
        config["search_limit"]
    )

    # 普通健康检测
    env["HEALTH_CANDIDATES"] = str(
        config["health_candidate_limit"]
    )

    env["HEALTHCHECK_MAX"] = str(
        config["health_candidate_limit"]
    )

    env["HEALTHCHECK_SUCCESS_TARGET"] = str(
        config["health_success_target"]
    )

    # CFW
    env["CFW_CANDIDATES"] = str(
        config["cfw_candidate_limit"]
    )

    env["CFW_HEALTH_TARGET"] = str(
        config["cfw_success_target"]
    )

    return env


# ============================================================
# 修改 sources.yaml 中的搜索上限
# ============================================================

def apply_search_limit(limit):

    source_file = ROOT / "sources.yaml"

    if not source_file.exists():
        return None

    try:
        import yaml
    except ImportError:
        print(
            "[warning] PyYAML 未安装，无法修改 sources.yaml。",
            flush=True,
        )
        return None

    original = source_file.read_text(
        encoding="utf-8"
    )

    data = yaml.safe_load(original) or {}

    if not isinstance(data, dict):
        return original

    scan = data.setdefault("scan", {})

    if isinstance(scan, dict):
        scan["max_aggregate_nodes"] = int(limit)

    source_file.write_text(
        yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    return original


# ============================================================
# 执行完整更新流程
# ============================================================

def run_pipeline():

    if not LOCK.acquire(False):

        return False

    config = get_config()

    STATE.update(
        running=True,
        last_start=datetime.now()
        .astimezone()
        .isoformat(),
        last_error=None,
    )

    logs = []

    success = False

    original_sources = None

    try:

        env = build_pipeline_environment(
            config
        )

        # ----------------------------------------------------
        # 搜索数量
        # ----------------------------------------------------

        original_sources = apply_search_limit(
            config["search_limit"]
        )

        # ----------------------------------------------------
        # 基础流程
        # ----------------------------------------------------

        basic_scripts = [
            "scanner.py",
            "augment_protocols.py",
            "select_nodes.py",
        ]

        for script in basic_scripts:

            script_path = ROOT / script

            if not script_path.exists():
                raise RuntimeError(
                    f"找不到 {script}"
                )

            process = subprocess.run(
                [sys.executable, script],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            logs.append(
                f"$ {script}\n{process.stdout}"
            )

            if process.returncode != 0:
                raise RuntimeError(
                    f"{script} exited with "
                    f"{process.returncode}"
                )

        # ----------------------------------------------------
        # 普通健康检测
        # ----------------------------------------------------

        env.update(
            {
                "HEALTHCHECK_MAX": str(
                    config["health_candidate_limit"]
                ),

                "HEALTHCHECK_SUCCESS_TARGET": str(
                    config["health_success_target"]
                ),

                "HEALTHCHECK_OUTPUT":
                    "health-checked-all.txt",

                "HEALTHCHECK_REPORT":
                    "healthcheck-all.json",
            }
        )

        healthcheck = ROOT / "healthcheck.py"

        if healthcheck.exists():

            process = subprocess.run(
                [sys.executable, "healthcheck.py"],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            logs.append(
                "$ healthcheck.py (general)\n"
                + process.stdout
            )

            if process.returncode != 0:

                raise RuntimeError(
                    "healthcheck.py general "
                    f"exited with {process.returncode}"
                )

        # ----------------------------------------------------
        # CFW 候选节点
        # ----------------------------------------------------

        candidates = (
            ROOT
            / "output"
            / "health-candidates.txt"
        )

        if candidates.exists():

            lines = candidates.read_text(
                encoding="utf-8",
                errors="ignore",
            ).splitlines()

            cfw_protocols = {
                "ss",
                "ssr",
                "vmess",
                "trojan",
            }

            compatible = []

            for line in lines:

                line = line.strip()

                if not line:
                    continue

                if "://" not in line:
                    continue

                protocol = (
                    line
                    .split("://", 1)[0]
                    .lower()
                )

                if protocol in cfw_protocols:

                    compatible.append(line)

            compatible = compatible[
                : config["cfw_candidate_limit"]
            ]

            verified = (
                ROOT
                / "output"
                / "verified-nodes.txt"
            )

            verified.write_text(
                "\n".join(compatible)
                + ("\n" if compatible else ""),
                encoding="utf-8",
            )

        # ----------------------------------------------------
        # CFW 健康检测
        # ----------------------------------------------------

        env.update(
            {
                "HEALTHCHECK_MAX": str(
                    config["cfw_candidate_limit"]
                ),

                "HEALTHCHECK_SUCCESS_TARGET": str(
                    config["cfw_success_target"]
                ),

                "HEALTHCHECK_TIMEOUT": "15",

                "HEALTHCHECK_ROUNDS": "3",

                "HEALTHCHECK_ROUND_DELAY": "1",

                "HEALTHCHECK_MIN_PUBLIC_TESTS": "2",

                "HEALTHCHECK_OUTPUT":
                    "health-checked-cfw.txt",

                "HEALTHCHECK_REPORT":
                    "healthcheck-cfw.json",
            }
        )

        if healthcheck.exists():

            process = subprocess.run(
                [sys.executable, "healthcheck.py"],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            logs.append(
                "$ healthcheck.py (CFW)\n"
                + process.stdout
            )

            if process.returncode != 0:

                raise RuntimeError(
                    "healthcheck.py CFW "
                    f"exited with {process.returncode}"
                )

        # ----------------------------------------------------
        # 发布输出
        # ----------------------------------------------------

        publisher = ROOT / "publish_outputs.py"

        if publisher.exists():

            process = subprocess.run(
                [sys.executable, "publish_outputs.py"],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            logs.append(
                "$ publish_outputs.py\n"
                + process.stdout
            )

            if process.returncode != 0:

                raise RuntimeError(
                    "publish_outputs.py "
                    f"exited with {process.returncode}"
                )

        success = True

    except Exception as exc:

        STATE["last_error"] = str(exc)

        logs.append(
            "ERROR: " + str(exc)
        )

    finally:

        # ----------------------------------------------------
        # 恢复 sources.yaml
        # ----------------------------------------------------

        if original_sources is not None:

            try:

                (
                    ROOT / "sources.yaml"
                ).write_text(
                    original_sources,
                    encoding="utf-8",
                )

            except Exception as exc:

                logs.append(
                    "WARNING: 无法恢复 "
                    f"sources.yaml: {exc}"
                )

        STATE.update(
            running=False,

            last_finish=datetime.now()
            .astimezone()
            .isoformat(),

            last_ok=success,

            last_output="\n\n".join(
                logs
            )[-30000:],
        )

        LOCK.release()

    return success


# ============================================================
# 下一次自动运行时间
# ============================================================

def next_run():

    config = get_config()

    timezone = ZoneInfo(
        config["timezone"]
    )

    now = datetime.now(timezone)

    hour, minute = parse_time(
        config["schedule_time"]
    )

    target = now.replace(
        hour=hour,
        minute=minute,
        second=0,
        microsecond=0,
    )

    if target <= now:
        target += timedelta(days=1)

    return target


# ============================================================
# 本地自动任务
# ============================================================

def scheduler():

    while True:

        try:

            target = next_run()

            now = datetime.now(
                target.tzinfo
            )

            seconds = (
                target - now
            ).total_seconds()

            time.sleep(
                max(1, seconds)
            )

            if not STATE["running"]:

                threading.Thread(
                    target=run_pipeline,
                    daemon=True,
                ).start()

            time.sleep(2)

        except Exception as exc:

            print(
                "[scheduler]",
                exc,
                flush=True,
            )

            time.sleep(30)


# ============================================================
# 管理员 Session
# ============================================================

def is_authenticated(handler):

    cookie = http.cookies.SimpleCookie()

    try:
        cookie.load(
            handler.headers.get(
                "Cookie",
                "",
            )
        )

    except Exception:

        return False

    session = cookie.get(
        "auto_vpn_admin"
    )

    return bool(
        session
        and session.value in SESSIONS
    )


def create_session(handler):

    token = secrets.token_urlsafe(32)

    SESSIONS.add(token)

    cookie = http.cookies.SimpleCookie()

    cookie["auto_vpn_admin"] = token

    cookie["auto_vpn_admin"]["path"] = "/"

    cookie["auto_vpn_admin"]["httponly"] = True

    cookie["auto_vpn_admin"]["samesite"] = "Strict"

    handler.send_header(
        "Set-Cookie",
        cookie.output(
            header=""
        ).strip(),
    )


# ============================================================
# JSON 响应
# ============================================================

def send_json(
    handler,
    data,
    status=200,
    headers=(),
):

    body = json.dumps(
        data,
        ensure_ascii=False,
    ).encode("utf-8")

    handler.send_response(status)

    handler.send_header(
        "Content-Type",
        "application/json; charset=utf-8",
    )

    handler.send_header(
        "Content-Length",
        str(len(body)),
    )

    handler.send_header(
        "Cache-Control",
        "no-store",
    )

    for key, value in headers:

        handler.send_header(
            key,
            value,
        )

    handler.end_headers()

    handler.wfile.write(body)


# ============================================================
# 登录页面
# ============================================================

LOGIN_HTML = """
<!doctype html>

<html lang="zh-CN">

<head>

<meta charset="utf-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>auto-vpnlink 管理员登录</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #f3f4f6;
    font-family: system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        "Microsoft YaHei",
        sans-serif;
}

.card {
    width: 420px;
    max-width: calc(100% - 32px);
    background: white;
    padding: 30px;
    border-radius: 18px;
    box-shadow: 0 15px 50px #0002;
}

input,
button {
    width: 100%;
    padding: 13px;
    margin-top: 12px;
    border-radius: 9px;
    border: 1px solid #ddd;
}

button {
    border: 0;
    background: #111827;
    color: white;
    cursor: pointer;
    font-weight: 600;
}

.error {
    color: #dc2626;
    margin-top: 12px;
}

</style>

</head>

<body>

<div class="card">

<h1>🔐 管理员登录</h1>

<form method="post"
action="/admin/login">

<input
type="password"
name="password"
placeholder="管理员密码"
autocomplete="current-password"
required>

<button type="submit">
登录
</button>

{{ERROR}}

</form>

</div>

</body>

</html>
"""


# ============================================================
# 管理员面板
# ============================================================

ADMIN_HTML = """
<!doctype html>

<html lang="zh-CN">

<head>

<meta charset="utf-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>auto-vpnlink 管理员面板</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #f3f4f6;
    color: #111827;
    font-family: system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        "Microsoft YaHei",
        sans-serif;
}

.container {
    width: 100%;
    max-width: 1000px;
    margin: 30px auto;
    padding: 18px;
}

.card {
    background: white;
    border-radius: 17px;
    padding: 24px;
    margin-bottom: 18px;
    box-shadow: 0 8px 25px #0001;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(2, minmax(0, 1fr));
    gap: 12px;
}

.info {
    border: 1px solid #e5e7eb;
    border-radius: 11px;
    padding: 13px;
}

label {
    display: block;
    margin-top: 13px;
    font-weight: 650;
}

input,
select,
button {
    width: 100%;
    padding: 11px;
    margin-top: 6px;
    border-radius: 9px;
    border: 1px solid #d1d5db;
    background: white;
}

button {
    margin-top: 16px;
    border: 0;
    background: #111827;
    color: white;
    cursor: pointer;
    font-weight: 650;
}

.hint {
    color: #6b7280;
    font-size: 13px;
    line-height: 1.6;
}

.success {
    margin-top: 12px;
    padding: 11px;
    border-radius: 9px;
    background: #ecfdf5;
    color: #166534;
}

.warning {
    margin-top: 12px;
    padding: 11px;
    border-radius: 9px;
    background: #fffbeb;
    color: #92400e;
}

.parameter-grid {
    display: grid;
    grid-template-columns:
        repeat(2, minmax(0, 1fr));
    gap: 12px;
}

.parameter-grid label:last-child {
    grid-column: 1 / -1;
}

@media(max-width: 650px) {

    .container {
        padding: 10px;
    }

    .card {
        padding: 19px;
    }

    .grid,
    .parameter-grid {
        grid-template-columns: 1fr;
    }

    .parameter-grid label:last-child {
        grid-column: auto;
    }

}

</style>

</head>

<body>

<div class="container">

<div class="card">

<h1>⚙️ auto-vpnlink 管理员面板</h1>

<div class="grid">

<div class="info">
服务器：
<b>{{HOST}}:{{PORT}}</b>
</div>

<div class="info">
自动运行：
<b id="schedule">{{TIME}}</b>
</div>

<div class="info">
时区：
<b id="timezone">{{TZ}}</b>
</div>

<div class="info">
下次运行：
<b id="next">-</b>
</div>

<div class="info">
运行状态：
<b id="running">-</b>
</div>

<div class="info">
上次结果：
<b id="result">-</b>
</div>

</div>

</div>


<div class="card">

<h2>⏰ 自动任务</h2>

<form id="scheduleForm">

<label>
每天运行时间

<input
id="time"
type="time"
value="{{TIME}}"
required>

</label>

<label>
IANA 时区

<select id="zone"></select>

</label>

<button>
保存自动任务设置
</button>

</form>

</div>


<div class="card">

<h2>🔎 搜索与健康检测参数</h2>

<p class="hint">

下面 5 个参数与 GitHub Actions
的 workflow_dispatch 参数保持一致。

本地自动任务和 Web 手动更新都会使用这里保存的参数。

</p>

<form id="parameterForm">

<div class="parameter-grid">

<label>

Maximum discovered nodes to consider

<input
id="search_limit"
type="number"
min="1"
max="20000"
value="{{SEARCH_LIMIT}}"
required>

</label>


<label>

Maximum nodes for general health check

<input
id="health_candidate_limit"
type="number"
min="1"
max="5000"
value="{{HEALTH_CANDIDATE_LIMIT}}"
required>

</label>


<label>

General healthy node target

<input
id="health_success_target"
type="number"
min="1"
max="5000"
value="{{HEALTH_SUCCESS_TARGET}}"
required>

</label>


<label>

Maximum CFW-compatible nodes to test

<input
id="cfw_candidate_limit"
type="number"
min="1"
max="2000"
value="{{CFW_CANDIDATE_LIMIT}}"
required>

</label>


<label>

CFW healthy node target

<input
id="cfw_success_target"
type="number"
min="1"
max="2000"
value="{{CFW_SUCCESS_TARGET}}"
required>

</label>

</div>

<button>
保存 5 个参数
</button>

</form>

<div id="parameterMessage"></div>

</div>


<div class="card">

<h2>▶️ 手动更新</h2>

<p class="hint">

立即执行一次更新任务。

当前保存的 5 个参数会自动应用。

</p>

<button id="runButton">
立即运行一次
</button>

<div id="runMessage"></div>

</div>


<div class="card">

<h2>🔑 管理员密码</h2>

<p class="hint">

密码只保存 PBKDF2 哈希。

随机密码只显示一次。

</p>

<form id="passwordForm">

<label>

自定义固定密码

<input
id="password"
type="password"
minlength="8"
placeholder="至少 8 位">

</label>

<button>
设置固定密码
</button>

</form>

<button id="randomPassword">
生成新的随机密码
</button>

<div id="passwordMessage"></div>

<p>

<a href="/admin/logout">
退出登录
</a>

</p>

</div>

</div>


<script>

"use strict";


const currentTimezone =
    "{{TZ}}";


const zone =
    document.getElementById("zone");


let timezones = [];


try {

    timezones =
        Intl.supportedValuesOf(
            "timeZone"
        );

} catch (error) {

    timezones = [];

}


if (!timezones.length) {

    timezones = [
        "UTC",
        "Asia/Shanghai",
        "Asia/Tokyo",
        "Asia/Hong_Kong",
        "Asia/Singapore",
        "Europe/London",
        "America/New_York",
        "America/Los_Angeles"
    ];

}


if (!timezones.includes(
    currentTimezone
)) {

    timezones.push(
        currentTimezone
    );

}


timezones
    .sort()
    .forEach(function(tz) {

        const option =
            document.createElement(
                "option"
            );

        option.value = tz;

        option.textContent = tz;

        if (tz === currentTimezone) {

            option.selected = true;

        }

        zone.appendChild(option);

    });


function showMessage(
    element,
    text,
    warning = false
) {

    element.className =
        warning
            ? "warning"
            : "success";

    element.textContent = text;

}


async function refreshStatus() {

    try {

        const response =
            await fetch(
                "/api/admin/status?" +
                Date.now(),
                {
                    cache: "no-store"
                }
            );

        const data =
            await response.json();


        if (!data.ok) {

            location.href =
                "/admin";

            return;

        }


        document
            .getElementById("schedule")
            .textContent =
                data.schedule_time;


        document
            .getElementById("timezone")
            .textContent =
                data.timezone;


        document
            .getElementById("time")
            .value =
                data.schedule_time;


        document
            .getElementById("next")
            .textContent =
                data.next_run;


        document
            .getElementById("running")
            .textContent =
                data.running
                    ? "运行中…"
                    : "空闲";


        document
            .getElementById("result")
            .textContent =
                data.last_ok === true
                    ? "成功"
                    : data.last_ok === false
                        ? "失败"
                        : "尚未运行";


        document
            .getElementById("search_limit")
            .value =
                data.search_limit;


        document
            .getElementById(
                "health_candidate_limit"
            )
            .value =
                data.health_candidate_limit;


        document
            .getElementById(
                "health_success_target"
            )
            .value =
                data.health_success_target;


        document
            .getElementById(
                "cfw_candidate_limit"
            )
            .value =
                data.cfw_candidate_limit;


        document
            .getElementById(
                "cfw_success_target"
            )
            .value =
                data.cfw_success_target;

    } catch (error) {

        console.error(error);

    }

}


document
    .getElementById("scheduleForm")
    .addEventListener(
        "submit",
        async function(event) {

            event.preventDefault();


            try {

                const response =
                    await fetch(
                        "/api/admin/schedule",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    schedule_time:
                                        document
                                            .getElementById(
                                                "time"
                                            )
                                            .value,

                                    timezone:
                                        zone.value
                                })
                        }
                    );


                const data =
                    await response.json();


                showMessage(
                    document
                        .getElementById(
                            "parameterMessage"
                        ),
                    data.ok
                        ? "自动任务设置已保存。"
                        : data.error,
                    !data.ok
                );


                refreshStatus();

            } catch (error) {

                console.error(error);

            }

        }
    );


document
    .getElementById("parameterForm")
    .addEventListener(
        "submit",
        async function(event) {

            event.preventDefault();


            const data = {

                search_limit:
                    Number(
                        document
                            .getElementById(
                                "search_limit"
                            )
                            .value
                    ),

                health_candidate_limit:
                    Number(
                        document
                            .getElementById(
                                "health_candidate_limit"
                            )
                            .value
                    ),

                health_success_target:
                    Number(
                        document
                            .getElementById(
                                "health_success_target"
                            )
                            .value
                    ),

                cfw_candidate_limit:
                    Number(
                        document
                            .getElementById(
                                "cfw_candidate_limit"
                            )
                            .value
                    ),

                cfw_success_target:
                    Number(
                        document
                            .getElementById(
                                "cfw_success_target"
                            )
                            .value
                    )

            };


            try {

                const response =
                    await fetch(
                        "/api/admin/parameters",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify(data)
                        }
                    );


                const result =
                    await response.json();


                showMessage(
                    document
                        .getElementById(
                            "parameterMessage"
                        ),
                    result.ok
                        ? "5 个参数已保存。"
                        : result.error,
                    !result.ok
                );


                refreshStatus();

            } catch (error) {

                console.error(error);

            }

        }
    );


document
    .getElementById("runButton")
    .addEventListener(
        "click",
        async function() {

            try {

                const response =
                    await fetch(
                        "/api/admin/run",
                        {
                            method: "POST"
                        }
                    );


                const data =
                    await response.json();


                showMessage(
                    document
                        .getElementById(
                            "runMessage"
                        ),
                    data.ok
                        ? "更新任务已经启动。"
                        : data.error,
                    !data.ok
                );


                refreshStatus();

            } catch (error) {

                console.error(error);

            }

        }
    );


document
    .getElementById("passwordForm")
    .addEventListener(
        "submit",
        async function(event) {

            event.preventDefault();


            const password =
                document
                    .getElementById(
                        "password"
                    )
                    .value;


            try {

                const response =
                    await fetch(
                        "/api/admin/password",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    password:
                                        password
                                })
                        }
                    );


                const data =
                    await response.json();


                showMessage(
                    document
                        .getElementById(
                            "passwordMessage"
                        ),
                    data.ok
                        ? "密码已经修改。"
                        : data.error,
                    !data.ok
                );


                if (data.ok) {

                    document
                        .getElementById(
                            "password"
                        )
                        .value = "";

                }

            } catch (error) {

                console.error(error);

            }

        }
    );


document
    .getElementById("randomPassword")
    .addEventListener(
        "click",
        async function() {

            if (
                !confirm(
                    "生成新的随机密码并立即使旧密码失效？"
                )
            ) {

                return;

            }


            try {

                const response =
                    await fetch(
                        "/api/admin/password",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    generate_random:
                                        true
                                })
                        }
                    );


                const data =
                    await response.json();


                if (data.ok) {

                    showMessage(
                        document
                            .getElementById(
                                "passwordMessage"
                            ),
                        "新随机密码：" +
                        data.password +
                        "　请立即保存。"
                    );

                } else {

                    showMessage(
                        document
                            .getElementById(
                                "passwordMessage"
                            ),
                        data.error,
                        true
                    );

                }

            } catch (error) {

                console.error(error);

            }

        }
    );


refreshStatus();

setInterval(
    refreshStatus,
    5000
);

</script>

</body>

</html>
"""


# ============================================================
# HTTP Server
# ============================================================

class Handler(BaseHTTPRequestHandler):

    def send_bytes(
        self,
        data,
        content_type="text/html; charset=utf-8",
        status=200,
        headers=(),
    ):

        self.send_response(status)

        self.send_header(
            "Content-Type",
            content_type,
        )

        self.send_header(
            "Content-Length",
            str(len(data)),
        )

        self.send_header(
            "Cache-Control",
            "no-store",
        )

        for key, value in headers:

            self.send_header(
                key,
                value,
            )

        self.end_headers()

        self.wfile.write(data)


    def read_json(self):

        try:

            length = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
            )

            body = self.rfile.read(
                length
            )

            return json.loads(
                body.decode("utf-8")
            )

        except Exception:

            return {}


    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    def do_GET(self):

        path = urlparse(
            self.path
        ).path


        # 管理员
        if path in (
            "/admin",
            "/admin/",
        ):

            if not is_authenticated(
                self
            ):

                return self.send_bytes(
                    LOGIN_HTML
                    .replace(
                        "{{ERROR}}",
                        "",
                    )
                    .encode("utf-8")
                )


            config = get_config()


            html = (
                ADMIN_HTML

                .replace(
                    "{{HOST}}",
                    HOST,
                )

                .replace(
                    "{{PORT}}",
                    str(PORT),
                )

                .replace(
                    "{{TIME}}",
                    config[
                        "schedule_time"
                    ],
                )

                .replace(
                    "{{TZ}}",
                    config[
                        "timezone"
                    ],
                )

                .replace(
                    "{{SEARCH_LIMIT}}",
                    str(
                        config[
                            "search_limit"
                        ]
                    ),
                )

                .replace(
                    "{{HEALTH_CANDIDATE_LIMIT}}",
                    str(
                        config[
                            "health_candidate_limit"
                        ]
                    ),
                )

                .replace(
                    "{{HEALTH_SUCCESS_TARGET}}",
                    str(
                        config[
                            "health_success_target"
                        ]
                    ),
                )

                .replace(
                    "{{CFW_CANDIDATE_LIMIT}}",
                    str(
                        config[
                            "cfw_candidate_limit"
                        ]
                    ),
                )

                .replace(
                    "{{CFW_SUCCESS_TARGET}}",
                    str(
                        config[
                            "cfw_success_target"
                        ]
                    ),
                )
            )


            return self.send_bytes(
                html.encode("utf-8")
            )


        # ----------------------------------------------------
        # 登出
        # ----------------------------------------------------

        if path == "/admin/logout":

            SESSIONS.clear()

            self.send_response(
                302
            )

            self.send_header(
                "Location",
                "/admin",
            )

            self.send_header(
                "Set-Cookie",
                "auto_vpn_admin=;"
                " Path=/;"
                " Max-Age=0;"
                " HttpOnly;"
                " SameSite=Strict",
            )

            self.end_headers()

            return


        # ----------------------------------------------------
        # 管理员状态
        # ----------------------------------------------------

        if path == "/api/admin/status":

            if not is_authenticated(
                self
            ):

                return send_json(
                    self,
                    {
                        "ok": False,
                        "error": "未登录",
                    },
                    401,
                )


            config = get_config()


            return send_json(
                self,
                {
                    **STATE,

                    "ok": True,

                    "schedule_time":
                        config[
                            "schedule_time"
                        ],

                    "timezone":
                        config[
                            "timezone"
                        ],

                    "next_run":
                        next_run()
                        .isoformat(),

                    "search_limit":
                        config[
                            "search_limit"
                        ],

                    "health_candidate_limit":
                        config[
                            "health_candidate_limit"
                        ],

                    "health_success_target":
                        config[
                            "health_success_target"
                        ],

                    "cfw_candidate_limit":
                        config[
                            "cfw_candidate_limit"
                        ],

                    "cfw_success_target":
                        config[
                            "cfw_success_target"
                        ],
                }
            )


        # ----------------------------------------------------
        # 本地状态 API
        #
        # subscriptions.html 会优先使用这个 API
        # ----------------------------------------------------

        if path == "/api/status":

            config = get_config()


            return send_json(
                self,
                {
                    "running":
                        STATE[
                            "running"
                        ],

                    "last_start":
                        STATE[
                            "last_start"
                        ],

                    "last_finish":
                        STATE[
                            "last_finish"
                        ],

                    "last_ok":
                        STATE[
                            "last_ok"
                        ],

                    "schedule_time":
                        config[
                            "schedule_time"
                        ],

                    "timezone":
                        config[
                            "timezone"
                        ],

                    "next_run":
                        next_run()
                        .isoformat(),

                    "search_limit":
                        config[
                            "search_limit"
                        ],

                    "health_candidate_limit":
                        config[
                            "health_candidate_limit"
                        ],

                    "health_success_target":
                        config[
                            "health_success_target"
                        ],

                    "cfw_candidate_limit":
                        config[
                            "cfw_candidate_limit"
                        ],

                    "cfw_success_target":
                        config[
                            "cfw_success_target"
                        ],
                }
            )


        # ----------------------------------------------------
        # 兼容 /api/run
        # ----------------------------------------------------

        if path == "/api/run":

            if not is_authenticated(
                self
            ):

                return send_json(
                    self,
                    {
                        "ok": False,
                        "error": "请先登录",
                    },
                    401,
                )


            if STATE["running"]:

                return send_json(
                    self,
                    {
                        "ok": False,
                        "error":
                            "任务正在运行",
                    },
                    409,
                )


            threading.Thread(
                target=run_pipeline,
                daemon=True,
            ).start()


            return send_json(
                self,
                {
                    "ok": True,
                },
                202,
            )


        # ----------------------------------------------------
        # 静态文件
        # ----------------------------------------------------

        relative_path = (
            path.lstrip("/")
            or "index.html"
        )

        target = (
            ROOT / relative_path
        ).resolve()


        try:

            if (
                ROOT not in target.parents
                and target != ROOT
            ):

                raise FileNotFoundError


            if not target.is_file():

                raise FileNotFoundError


            data = target.read_bytes()

            extension = (
                target.suffix.lower()
            )


            content_type = (
                "text/plain; charset=utf-8"
            )


            if extension in (
                ".html",
                ".htm",
            ):

                content_type = (
                    "text/html; charset=utf-8"
                )

            elif extension == ".json":

                content_type = (
                    "application/json; charset=utf-8"
                )

            elif extension == ".css":

                content_type = (
                    "text/css; charset=utf-8"
                )

            elif extension == ".js":

                content_type = (
                    "application/javascript; charset=utf-8"
                )

            elif extension in (
                ".yaml",
                ".yml",
            ):

                content_type = (
                    "text/yaml; charset=utf-8"
                )


            return self.send_bytes(
                data,
                content_type,
            )


        except Exception:

            return self.send_bytes(
                b"404 Not Found",
                "text/plain; charset=utf-8",
                404,
            )


    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    def do_POST(self):

        path = urlparse(
            self.path
        ).path


        # ----------------------------------------------------
        # 登录
        # ----------------------------------------------------

        if path == "/admin/login":

            length = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
            )

            body = self.rfile.read(
                length
            ).decode("utf-8")


            query = parse_qs(
                body
            )


            password = query.get(
                "password",
                [""],
            )[0]


            config = get_config()


            if verify_password(
                password,
                config[
                    "password_salt"
                ],
                config[
                    "password_hash"
                ],
            ):

                self.send_response(
                    302
                )

                self.send_header(
                    "Location",
                    "/admin",
                )

                create_session(
                    self
                )

                self.end_headers()

                return


            html = LOGIN_HTML.replace(
                "{{ERROR}}",
                '<div class="error">'
                '密码错误'
                '</div>',
            )


            return self.send_bytes(
                html.encode("utf-8"),
                status=401,
            )


        # ----------------------------------------------------
        # 下面全部需要登录
        # ----------------------------------------------------

        protected_paths = {
            "/api/admin/run",
            "/api/admin/schedule",
            "/api/admin/parameters",
            "/api/admin/password",
        }


        if (
            path in protected_paths
            and not is_authenticated(
                self
            )
        ):

            return send_json(
                self,
                {
                    "ok": False,
                    "error": "未登录",
                },
                401,
            )


        # ----------------------------------------------------
        # 手动运行
        # ----------------------------------------------------

        if path == "/api/admin/run":

            if STATE["running"]:

                return send_json(
                    self,
                    {
                        "ok": False,
                        "error":
                            "任务正在运行",
                    },
                    409,
                )


            threading.Thread(
                target=run_pipeline,
                daemon=True,
            ).start()


            return send_json(
                self,
                {
                    "ok": True,
                },
                202,
            )


        # ----------------------------------------------------
        # 修改自动任务
        # ----------------------------------------------------

        if path == "/api/admin/schedule":

            data = self.read_json()


            try:

                parse_time(
                    data["schedule_time"]
                )

                valid_tz(
                    data["timezone"]
                )


                update_config(
                    schedule_time=
                        data["schedule_time"],

                    timezone=
                        data["timezone"],
                )


                return send_json(
                    self,
                    {
                        "ok": True,
                    }
                )


            except Exception as exc:

                return send_json(
                    self,
                    {
                        "ok": False,
                        "error": str(exc),
                    },
                    400,
                )


        # ----------------------------------------------------
        # 修改五个参数
        # ----------------------------------------------------

        if path == "/api/admin/parameters":

            data = self.read_json()


            try:

                parameters = validate_parameters(
                        data
                    )


                update_config(
                    **parameters
                )


                return send_json(
                    self,
                    {
                        "ok": True,
                        **parameters,
                    }
                )


            except Exception as exc:

                return send_json(
                    self,
                    {
                        "ok": False,
                        "error": str(exc),
                    },
                    400,
                )


        # ----------------------------------------------------
        # 修改管理员密码
        # ----------------------------------------------------

        if path == "/api/admin/password":

            data = self.read_json()


            if data.get(
                "generate_random"
            ):

                password = random_password()

            else:

                password = str(
                        data.get(
                            "password",
                            "",
                        )
                    )


                if len(password) < 8:

                    return send_json(
                        self,
                        {
                            "ok": False,
                            "error":
                                "密码至少 8 位",
                        },
                        400,
                    )


            salt, digest = hash_password(
                    password
                )


            update_config(
                password_salt=salt,
                password_hash=digest,
            )


            # 修改密码后让旧 Session 全部失效
            SESSIONS.clear()


            # 给当前浏览器重新创建 Session
            token = secrets.token_urlsafe(
                    32
                )

            SESSIONS.add(token)


            cookie = http.cookies.SimpleCookie()

            cookie[
                "auto_vpn_admin"
            ] = token

            cookie[
                "auto_vpn_admin"
            ]["path"] = "/"

            cookie[
                "auto_vpn_admin"
            ]["httponly"] = True

            cookie[
                "auto_vpn_admin"
            ]["samesite"] = "Strict"


            return send_json(
                self,
                {
                    "ok": True,

                    **(
                        {
                            "password":
                                password
                        }

                        if data.get(
                            "generate_random"
                        )

                        else {}
                    ),
                },

                headers=[
                    (
                        "Set-Cookie",
                        cookie.output(
                            header=""
                        ).strip(),
                    )
                ],
            )


        return send_json(
            self,
            {
                "ok": False,
                "error": "Unknown endpoint",
            },
            404,
        )


    def log_message(
        self,
        format_string,
        *args,
    ):

        print(
            "[web] "
            + format_string % args,
            flush=True,
        )


# ============================================================
# 启动
# ============================================================

def main():

    print()
    print("=" * 70)
    print("auto-vpnlink Local Server")
    print("=" * 70)

    print(
        f"Web:   http://127.0.0.1:{PORT}/"
    )

    print(
        f"Admin: http://127.0.0.1:{PORT}/admin"
    )

    print(
        f"Listen: {HOST}:{PORT}"
    )

    print("=" * 70)
    print()


    # 启动本地自动任务
    threading.Thread(
        target=scheduler,
        daemon=True,
    ).start()


    server = ThreadingHTTPServer(
            (HOST, PORT),
            Handler,
        )


    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print(
            "\n正在关闭服务器..."
        )

    finally:

        server.server_close()


if __name__ == "__main__":

    main()
