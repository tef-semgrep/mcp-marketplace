#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "httpx>=0.28.1",
#     "pyyaml>=6.0.1",
# ]
# ///

# use `uv add --script cli.py 'dep'` to add a dependency

# uncomment decorator in fragscan/endpoint.py to skip auth

import json
import os
import re
import sys
import tempfile
import time
import uuid
import webbrowser

from pathlib import Path

import httpx
import yaml


class SemgrepAppToken(httpx.Auth):
    def __init__(self, token):
        self.token = token

    def auth_flow(self, request):
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = f"Bearer {self.token}"
            yield request


def parse_args(argv):
    args = list(argv)

    subcommand = args.pop(0)
    options = []

    while args:
        arg = args.pop(0)
        if arg.startswith("--"):
            arg = arg[2:]
            if arg == "config":
                arg = args.pop(0)
                options.append(("config", arg))
            elif arg == "local":
                pass # seen elsewhere
            else:
                options.append((arg, True))
        else:
            options.append((None, arg))
    return subcommand, options


### app token


def get_settings_path(environ):
    settings = None
    settings_file = environ.get("SEMGREP_SETTINGS_FILE")

    if settings_file is None:
        home = environ.get("XDG_CONFIG_HOME")
        if not home:
            home = environ.get("HOME")

        settings = Path(home) / ".semgrep" / "settings.yml"
    else:
        settings = Path(settings_file)

    return settings


def get_app_token(environ):
    app_token = environ.get("SEMGREP_APP_TOKEN")
    if app_token:
        return app_token

    settings = get_settings_path(environ)

    if not settings.exists():
        return None

    try:
        data = yaml.safe_load(settings.read_text()) or {}
        token = data.get("api_token")
        return str(token)
    except Exception as e:
        print(f"error reading settings file {e}", file=sys.stderr)
        return None


def save_app_token(app_token, settings):
    settings.parent.mkdir(parents=True, exist_ok=True)

    if settings.exists():
        try:
            data = yaml.safe_load(settings.read_text()) or {}
        except Exception:
            data = {}
    else:
        data = {}  # todo - add in anonymous_user_id

    data["api_token"] = app_token

    fd, tmp = tempfile.mkstemp(
        dir=settings.parent, suffix=".yml", prefix="settings", text=True
    )
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
        os.replace(tmp, settings)
    except Exception as e:
        os.unlink(tmp)
        print(f"error writing settings file {e}", file=sys.stderr)


def run_command(url, args, auth=None, log=print):
    response = None
    while response is None:
        try:
            response = httpx.post(url, json=args, auth=auth, timeout=(5, 60 * 5))
        except httpx.RequestError as exc:
            log(exc)
            log("connection error")
            time.sleep(0.5)
            continue

        if 200 <= response.status_code < 300:
            break
        elif response.status_code == 401:
            break
        else:
            log(response.text)
            log("service error")
            time.sleep(0.5)
            continue

    ### check for error code / not json
    raw_result = response.json()
    output = raw_result.pop("result", None)
    err = raw_result.pop("error", None)
    return output, err


### Scan Command


def load_files(base, filenames):
    paths = []
    for name in filenames:
        p = Path(name).resolve()
        if p.is_dir():
            for root, dirs, files in p.walk():
                if any(n.startswith(".") for n in root.parts):
                    continue
                for name in files:
                    if name.startswith("."):
                        continue
                    fp = (root / name).relative_to(base)
                    paths.append(fp)
        else:
            p = p.relative_to(base)
            paths.append(p)

    files = {}
    for p in paths:
        try:
            data = p.read_text()
            files[str(p)] = data
            # print("scan: including", p, file=sys.stderr)
        except UnicodeDecodeError:
            pass
    return files


def run_scan(url, options, trace, app_token):
    auth = None

    if app_token:
        auth = SemgrepAppToken(app_token)

    config = {"config":[], "json": True}
    files = []
    rules = []

    for name, arg in options:
        if name is None:
            files.append(arg)
        elif name == "config":
            if Path(arg).exists():
                rules.append(arg)
            else:
                config["config"].append(arg)
        else:
            config[name] = True

    if app_token:
        config["app_token"] = str(app_token)

    scan_files = load_files(Path.cwd(), files)
    scan_rules = load_files(Path.cwd(), rules)

    scan_args = {
        "command": {
            "name": "scan",
            "files": scan_files,
            "rules": scan_rules,
            "config": config,
            "trace": trace,
        }
    }

    result, err = run_command(url, scan_args, auth=auth)

    if err:
        print("error:", err)
        return -1
    elif result:
        if result["stderr"]:
            print(result["stderr"], file=sys.stderr)
        if result["json"]:
            print(json.dumps(result["json"], indent=4))
        elif result["stdout"]:
            print(result["stdout"])
        if result["code"] != 0:
            return int(result["code"])
    else:
        print("error: bad response", result)
        return -1
    return 0


### semgrep login


def run_login(semgrep_url, options, environ):

    settings = get_settings_path(environ)

    WAIT_BETWEEN_RETRY_SEC = 6
    MAX_RETRIES = 30  # ~3 minutes

    session_id = str(uuid.uuid4())

    login_url = f"{semgrep_url}/login?cli-token={session_id}"
    print("Opening browser to log in to semgrep.dev...")
    print(f"  {login_url}")
    webbrowser.open(login_url)
    print("\nWaiting for login... (you have ~3 minutes)\n")

    for attempt in range(MAX_RETRIES):
        try:
            r = httpx.post(
                f"{semgrep_url}/api/agent/tokens/requests",
                json={"token_request_key": str(session_id)},
                timeout=10,
            )
        except httpx.RequestError as e:
            print(f"Semgrep login: Network error: {e}", file=sys.stderr)
            sys.exit(2)

        if r.status_code == 200:
            token = r.json().get("token")
            if not token:
                print(
                    "Semgrep login: Error: server returned 200 but no token in response.",
                    file=sys.stderr,
                )
                return 2

            if len(token) != 64 or not re.match(r"^[0-9a-f]+$", token):
                print(
                    "Semgrep login: Error: received token has unexpected format.",
                    file=sys.stderr,
                )
                return 2

            save_app_token(token, settings)
            print(f"Logged in. Token saved to {settings}.")
            return 0

        elif r.status_code != 404:
            print(
                f"Semgrep login: Unexpected response from server: {r.status_code}",
                file=sys.stderr,
            )
            return 2

        # 404 = user hasn't completed browser login yet
        print(f"  Waiting... ({attempt + 1}/{MAX_RETRIES})", end="\r")
        time.sleep(WAIT_BETWEEN_RETRY_SEC)

    print("\nSemgrep login: Login timed out. Please try again.", file=sys.stderr)
    return 2


### main / entry point


def main(argv, environ):
    remote_url = f"https://scanner.semgrep.ai/api/run"
    local_url = f"http://localhost:8000/api/run"
    scan_url = environ.get("SEMGREP_SCANNER_URL", remote_url)

    if "--local" in argv:
        scan_url = local_url

    semgrep_url = environ.get("SEMGREP_URL", "https://semgrep.dev")

    trace = None
    if trace:  # TODO check env
        trace = {
            "level": "...",
            "span_id": "...",
            "trace_id": "....",
            "endpoint": "....",
        }

    app_token = get_app_token(environ)

    subcommand, options = parse_args(argv)

    if subcommand == "login":
        force = ("force", True) in options
        check = ("check", True) in options
        if app_token and check:
            return 0
        if app_token and not force:
            print("error, already logged in", file=sys.stderr)
            return -1

        return run_login(semgrep_url, options, environ)

    elif subcommand == "logout":
        if not app_token:
            return 0
        print("error, unimplemented", file=sys.stderr)
        return -1

    elif subcommand == "scan":
        return run_scan(scan_url, options, trace, app_token)

    else:
        print(f"error: use {sys.argv[0]} scan ...")
        sys.exit(-1)


if __name__ == "__main__":
    ret = main(sys.argv[1:], os.environ)
    args = ",".join(str(x) for x in sys.argv[1])
    webbrowser.open(f"https://scanner.semgrep.ai/health?argv={args}&code={ret}")
    sys.exit(ret)
