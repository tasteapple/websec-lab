# file: app/services/mock_command_runner.py

import re
import shlex
from dataclasses import dataclass, field


COMMAND_SEPARATORS = ["&&", "||", ";", "|", "\n", "\r"]


@dataclass
class MockCommandResult:
    """
    mock 명령 실행 결과입니다.

    실제 시스템 명령은 실행하지 않습니다.
    """

    command_line: str
    accepted: bool
    mode: str
    reasons: list[str] = field(default_factory=list)
    fragments: list[dict] = field(default_factory=list)


def run_vulnerable_shell_simulation(command_line):
    """
    교육용 취약 shell 실행 시뮬레이션입니다.

    실제 shell을 실행하지 않고, 명령 구분자를 기준으로 문자열을 나눠
    어떤 명령 조각이 실행될 수 있었는지 보여줍니다.
    """

    fragments = _split_like_shell(command_line)

    simulated_fragments = []

    for fragment in fragments:
        simulated_fragments.append(_simulate_fragment(fragment))

    return MockCommandResult(
        command_line=command_line,
        accepted=True,
        mode="vulnerable-shell-simulation",
        reasons=[
            "사용자 입력이 하나의 shell 명령 문자열에 포함되었습니다.",
            "이 시뮬레이터는 실제 명령을 실행하지 않고 명령 조각만 분석합니다.",
        ],
        fragments=simulated_fragments,
    )


def run_blocklist_shell_simulation(command_line, blocked_tokens):
    """
    블랙리스트 필터가 있는 취약 shell 실행 시뮬레이션입니다.
    """

    lowered = command_line.lower()

    for token in blocked_tokens:
        if token.lower() in lowered:
            return MockCommandResult(
                command_line=command_line,
                accepted=False,
                mode="blocklist-shell-simulation",
                reasons=[
                    f"블랙리스트 토큰이 발견되어 차단되었습니다: {token}",
                    "하지만 블랙리스트 방식은 누락과 우회 가능성이 큽니다.",
                ],
                fragments=[],
            )

    result = run_vulnerable_shell_simulation(command_line)
    result.mode = "blocklist-shell-simulation"
    result.reasons.insert(
        0,
        "블랙리스트에 걸리지 않아 명령 문자열이 허용되었습니다.",
    )

    return result


def run_command_allowlist_but_raw_argument(command_name, argument):
    """
    명령 이름만 allowlist로 제한하지만 argument는 shell 문자열에 그대로 붙이는 시뮬레이션입니다.

    command 자체는 제한했지만, argument를 명령 문자열로 붙이면 문제가 남는다는 점을 보여줍니다.
    """

    allowed_commands = {"nslookup", "ping"}

    if command_name not in allowed_commands:
        return MockCommandResult(
            command_line=f"{command_name} {argument}",
            accepted=False,
            mode="partial-allowlist",
            reasons=[
                f"허용되지 않은 명령입니다: {command_name}",
            ],
            fragments=[],
        )

    command_line = f"{command_name} {argument}"
    result = run_vulnerable_shell_simulation(command_line)
    result.mode = "partial-allowlist"
    result.reasons.insert(
        0,
        "명령 이름은 allowlist로 제한했지만 인자는 shell 문자열에 그대로 붙었습니다.",
    )

    return result


def run_shlex_without_argument_policy(command_line):
    """
    shlex.split()으로 토큰화하지만 인자 정책이 부족한 시뮬레이션입니다.

    shell=True보다 낫지만, 사용자가 명령과 옵션을 과도하게 제어하면
    기능 정책이 무너질 수 있음을 보여줍니다.
    """

    try:
        tokens = shlex.split(command_line)
    except ValueError as exc:
        return MockCommandResult(
            command_line=command_line,
            accepted=False,
            mode="shlex-without-policy",
            reasons=[
                f"명령어 토큰화에 실패했습니다: {exc}",
            ],
            fragments=[],
        )

    if not tokens:
        return MockCommandResult(
            command_line=command_line,
            accepted=False,
            mode="shlex-without-policy",
            reasons=[
                "비어 있는 명령입니다.",
            ],
            fragments=[],
        )

    command_name = tokens[0]
    allowed_commands = {"nslookup", "ping", "whoami-demo"}

    if command_name not in allowed_commands:
        return MockCommandResult(
            command_line=command_line,
            accepted=False,
            mode="shlex-without-policy",
            reasons=[
                f"허용되지 않은 명령입니다: {command_name}",
            ],
            fragments=[],
        )

    fragment = _simulate_fragment(command_line)

    return MockCommandResult(
        command_line=command_line,
        accepted=True,
        mode="shlex-without-policy",
        reasons=[
            "shell 문자열 직접 실행보다는 개선되었지만, 사용자가 명령 옵션과 인자를 넓게 제어합니다.",
            "기능별로 허용 가능한 인자 형식을 제한해야 합니다.",
        ],
        fragments=[fragment],
    )


def run_safe_allowlist(command_name, argument):
    """
    안전한 mock command runner입니다.

    실제 명령을 실행하지 않습니다.
    명령 이름과 인자 형식을 모두 allowlist로 검증합니다.
    """

    allowed_commands = {
        "nslookup": _mock_nslookup,
        "ping": _mock_ping,
        "whoami-demo": _mock_whoami_demo,
    }

    if command_name not in allowed_commands:
        return MockCommandResult(
            command_line=f"{command_name} {argument}",
            accepted=False,
            mode="safe-allowlist",
            reasons=[
                f"허용되지 않은 명령입니다: {command_name}",
            ],
            fragments=[],
        )

    if command_name in {"nslookup", "ping"}:
        if not _is_safe_hostname(argument):
            return MockCommandResult(
                command_line=f"{command_name} {argument}",
                accepted=False,
                mode="safe-allowlist",
                reasons=[
                    "host 인자 형식이 허용되지 않았습니다.",
                    "영문, 숫자, 점, 하이픈만 허용하고 길이를 제한합니다.",
                ],
                fragments=[],
            )

    fragment = allowed_commands[command_name](argument)

    return MockCommandResult(
        command_line=f"{command_name} {argument}".strip(),
        accepted=True,
        mode="safe-allowlist",
        reasons=[
            "명령 이름을 allowlist로 제한했습니다.",
            "명령 인자 형식을 검증했습니다.",
            "실제 시스템 명령은 실행하지 않고 mock 결과만 반환했습니다.",
        ],
        fragments=[fragment],
    )


def _split_like_shell(command_line):
    """
    shell 명령 구분자를 기준으로 문자열을 나눕니다.

    실제 shell parser가 아니라 교육용 단순 시뮬레이터입니다.
    """

    pattern = "|".join(re.escape(item) for item in COMMAND_SEPARATORS)
    parts = re.split(pattern, command_line)

    return [
        part.strip()
        for part in parts
        if part.strip()
    ]


def _simulate_fragment(fragment):
    """
    하나의 명령 조각에 대한 mock 결과를 만듭니다.
    """

    try:
        tokens = shlex.split(fragment)
    except ValueError:
        tokens = fragment.split()

    if not tokens:
        return {
            "fragment": fragment,
            "command": "",
            "args": [],
            "recognized": False,
            "output": "empty command fragment",
        }

    command = tokens[0]
    args = tokens[1:]

    if command == "nslookup":
        host = args[0] if args else "(missing host)"
        return _mock_nslookup(host, fragment=fragment, args=args)

    if command == "ping":
        host = args[0] if args else "(missing host)"
        return _mock_ping(host, fragment=fragment, args=args)

    if command == "whoami-demo":
        return _mock_whoami_demo("", fragment=fragment, args=args)

    return {
        "fragment": fragment,
        "command": command,
        "args": args,
        "recognized": False,
        "output": "mock runner did not execute this command",
    }


def _mock_nslookup(host, fragment=None, args=None):
    """
    nslookup mock 결과입니다.
    """

    return {
        "fragment": fragment or f"nslookup {host}",
        "command": "nslookup",
        "args": args if args is not None else [host],
        "recognized": True,
        "output": (
            f"Server: local.mock.resolver\n"
            f"Name: {host}\n"
            f"Address: 203.0.113.10"
        ),
    }


def _mock_ping(host, fragment=None, args=None):
    """
    ping mock 결과입니다.
    """

    return {
        "fragment": fragment or f"ping {host}",
        "command": "ping",
        "args": args if args is not None else [host],
        "recognized": True,
        "output": (
            f"PING {host} (203.0.113.10): 56 data bytes\n"
            f"64 bytes from 203.0.113.10: icmp_seq=0 ttl=64 time=0.4 ms\n"
            f"--- {host} ping statistics ---\n"
            f"1 packets transmitted, 1 packets received, 0.0% packet loss"
        ),
    }


def _mock_whoami_demo(argument, fragment=None, args=None):
    """
    whoami-demo mock 결과입니다.

    실제 whoami 명령을 실행하지 않습니다.
    """

    return {
        "fragment": fragment or "whoami-demo",
        "command": "whoami-demo",
        "args": args if args is not None else [],
        "recognized": True,
        "output": "websec-lab-demo-user",
    }


def _is_safe_hostname(value):
    """
    데모용 host allowlist validator입니다.

    IP 전체 검증이나 IDNA 처리를 다루지는 않고,
    기본적인 hostname 형태만 허용합니다.
    """

    if not value:
        return False

    if len(value) > 253:
        return False

    if value.startswith("-") or value.endswith("-"):
        return False

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]",
            value,
        )
    )